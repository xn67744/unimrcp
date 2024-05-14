/*
 * Copyright 2008-2015 Arsen Chaloyan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * Mandatory rules concerning plugin implementation.
 * 1. Each plugin MUST implement a plugin/engine creator function
 *    with the exact signature and name (the main entry point)
 *        MRCP_PLUGIN_DECLARE(mrcp_engine_t*) mrcp_plugin_create(apr_pool_t *pool)
 * 2. Each plugin MUST declare its version number
 *        MRCP_PLUGIN_VERSION_DECLARE
 * 3. One and only one response MUST be sent back to the received request.
 * 4. Methods (callbacks) of the MRCP engine channel MUST not block.
 *   (asynchronous response can be sent from the context of other thread)
 * 5. Methods (callbacks) of the MPF engine stream MUST not block.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <libwebsockets.h>
#include "mrcp_recog_engine.h"
#include "mpf_activity_detector.h"
#include "apt_consumer_task.h"
#include "apt_log.h"
#include <json-c/json.h>
#include <apr_hash.h>
#include <apr_uuid.h>

#define RECOG_ENGINE_TASK_NAME "Funasr Recog Engine"

typedef struct funasr_recog_engine_t funasr_recog_engine_t;
typedef struct funasr_recog_channel_t funasr_recog_channel_t;
typedef struct funasr_recog_msg_t funasr_recog_msg_t;

/** Declaration of recognizer engine methods */
static apt_bool_t funasr_recog_engine_destroy(mrcp_engine_t *engine);
static apt_bool_t funasr_recog_engine_open(mrcp_engine_t *engine);
static apt_bool_t funasr_recog_engine_close(mrcp_engine_t *engine);
static mrcp_engine_channel_t* funasr_recog_engine_channel_create(mrcp_engine_t *engine, apr_pool_t *pool);

static const struct mrcp_engine_method_vtable_t engine_vtable = {
	funasr_recog_engine_destroy,
	funasr_recog_engine_open,
	funasr_recog_engine_close,
	funasr_recog_engine_channel_create
};


/** Declaration of recognizer channel methods */
static apt_bool_t funasr_recog_channel_destroy(mrcp_engine_channel_t *channel);
static apt_bool_t funasr_recog_channel_open(mrcp_engine_channel_t *channel);
static apt_bool_t funasr_recog_channel_close(mrcp_engine_channel_t *channel);
static apt_bool_t funasr_recog_channel_request_process(mrcp_engine_channel_t *channel, mrcp_message_t *request);

static const struct mrcp_engine_channel_method_vtable_t channel_vtable = {
	funasr_recog_channel_destroy,
	funasr_recog_channel_open,
	funasr_recog_channel_close,
	funasr_recog_channel_request_process
};

/** Declaration of recognizer audio stream methods */
static apt_bool_t funasr_recog_stream_destroy(mpf_audio_stream_t *stream);
static apt_bool_t funasr_recog_stream_open(mpf_audio_stream_t *stream, mpf_codec_t *codec);
static apt_bool_t funasr_recog_stream_close(mpf_audio_stream_t *stream);
static apt_bool_t funasr_recog_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame);

static const mpf_audio_stream_vtable_t audio_stream_vtable = {
	funasr_recog_stream_destroy,
	NULL,
	NULL,
	NULL,
	funasr_recog_stream_open,
	funasr_recog_stream_close,
	funasr_recog_stream_write,
	NULL
};

/** Declaration of demo recognizer channel */
struct funasr_recog_channel_t {
	/** Back pointer to engine */
	funasr_recog_engine_t     *funasr_engine;
	/** Engine channel base */
	mrcp_engine_channel_t   *channel;

	/** Active (in-progress) recognition request */
	mrcp_message_t          *recog_request;
	/** Pending stop response */
	mrcp_message_t          *stop_response;
	/** Indicates whether input timers are started */
	apt_bool_t               timers_started;
	/** Voice activity detector */
	mpf_activity_detector_t *detector;
	/** File to write utterance to */
	FILE                    *audio_out;
	char*               uuid;
};

typedef enum {
	FUNASR_RECOG_MSG_OPEN_CHANNEL,
	FUNASR_RECOG_MSG_CLOSE_CHANNEL,
	FUNASR_RECOG_MSG_REQUEST_PROCESS
} funasr_recog_msg_type_e;

/** Declaration of demo recognizer task message */
struct funasr_recog_msg_t {
	funasr_recog_msg_type_e  type;
	mrcp_engine_channel_t *channel; 
	mrcp_message_t        *request;
};

// 初始化哈希表，通常在某个初始化函数中
static apr_hash_t *websocket_channel_map;

static void process_asr_result(const char* result, size_t size) {
	json_object* parsed_json, * jtext, * jmodel, * wav_name_obj;

	// 解析JSON数据
	json_tokener* tok = json_tokener_new();
	parsed_json = json_tokener_parse_ex(tok, result, size);
	json_tokener_free(tok);

	// 检查并获取"text"和"is_final"字段
	if (json_object_object_get_ex(parsed_json, "text", &jtext) &&
		json_object_object_get_ex(parsed_json, "mode", &jmodel)) {
		const char* text = json_object_get_string(jtext);
		const char* model = json_object_get_string(jmodel);
		json_object_object_get_ex(parsed_json, "wav_name", &wav_name_obj);
		const char* wav_name = json_object_get_string(wav_name_obj);
		// 如果识别过程结束，则发送识别完成的消息;
		if (model && strcmp(model, "2pass-offline") == 0) {
			apt_log(APT_LOG_MARK, APT_PRIO_INFO, "处理asr识别结果获取channel的wav_name: %s, 识别的结果 %s", wav_name, text);
			funasr_recog_channel_t* channel = (funasr_recog_channel_t*)apr_hash_get(websocket_channel_map, wav_name, APR_HASH_KEY_STRING);
			mrcp_message_t* message = mrcp_event_create(channel->recog_request, RECOGNIZER_RECOGNITION_COMPLETE, channel->recog_request->pool);
			if (message) {
				// 设置识别结果文本
				apt_string_set(&message->body, text);
				message->start_line.request_state = MRCP_REQUEST_STATE_COMPLETE;

				// 发送消息
				mrcp_engine_channel_message_send(channel->channel, message);
				channel->recog_request = NULL;
			}
		}
	}
	// 清理JSON对象
	json_object_put(parsed_json);
}

// 构建初始 FUNASRJSON 消息
static unsigned char* create_initial_json_message(size_t* out_size, const char** out_str, char* wav_name) {
	json_object* json_msg = json_object_new_object();
	json_object_object_add(json_msg, "mode", json_object_new_string("2pass"));
	json_object_object_add(json_msg, "wav_name", json_object_new_string(wav_name));
	json_object_object_add(json_msg, "is_speaking", json_object_new_boolean(1));
	json_object_object_add(json_msg, "wav_format", json_object_new_string("pcm"));

	json_object* chunk_size_array = json_object_new_array();
	json_object_array_add(chunk_size_array, json_object_new_int(5));
	json_object_array_add(chunk_size_array, json_object_new_int(10));
	json_object_array_add(chunk_size_array, json_object_new_int(5));
	json_object_object_add(json_msg, "chunk_size", chunk_size_array);

	const char* json_str = json_object_to_json_string_ext(json_msg, JSON_C_TO_STRING_PLAIN);
	size_t json_str_len = strlen(json_str);
	*out_str = _strdup(json_str);

	size_t buffer_size = LWS_SEND_BUFFER_PRE_PADDING + json_str_len + LWS_SEND_BUFFER_POST_PADDING;
	unsigned char* buffer = (unsigned char*)malloc(buffer_size);
	if (buffer) {
		memcpy(buffer + LWS_SEND_BUFFER_PRE_PADDING, json_str, json_str_len);
		*out_size = json_str_len;
	}

	json_object_put(json_msg);

	return buffer;
}

// 构建最终 FUNASRJSON 消息
static unsigned char* create_final_json_message(size_t* out_size, const char** out_str) {
	json_object* json_msg = json_object_new_object();
	json_object_object_add(json_msg, "is_speaking", json_object_new_boolean(0));

	const char* json_str = json_object_to_json_string_ext(json_msg, JSON_C_TO_STRING_PLAIN);
	size_t json_str_len = strlen(json_str);
	*out_str = _strdup(json_str);

	size_t buffer_size = LWS_SEND_BUFFER_PRE_PADDING + json_str_len + LWS_SEND_BUFFER_POST_PADDING;
	unsigned char* buffer = (unsigned char*)malloc(buffer_size);
	if (buffer) {
		memcpy(buffer + LWS_SEND_BUFFER_PRE_PADDING, json_str, json_str_len);
		*out_size = json_str_len;
	}

	json_object_put(json_msg);

	return buffer;
}

// websocket回调函数
static int callback_funws(struct lws* wsi, enum lws_callback_reasons reason, void* user, void* in, size_t len) {
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		apt_log(APT_LOG_MARK, APT_PRIO_WARNING, "WebSocket connection error: %s", (const char*)in);
		break;
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		apt_log(APT_LOG_MARK, APT_PRIO_INFO, "WebSocket connection established");
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		apt_log(APT_LOG_MARK, APT_PRIO_INFO, "Received data: %.*s\n", (int)len, (char*)in);
		process_asr_result((const char*)in, len);
		break;
	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{
		"default", // 协议名称
		callback_funws, // 回调函数
		0, // per_session_data_size
		0, // rx_buffer_size
	},
	{ NULL, NULL, 0, 0 } // 结束标志
};

/** 定义websocket结构体 **/
typedef struct funasr_recog_engine_t {
	apt_consumer_task_t* task;
	struct lws_context* websocket_context;  // WebSocket 上下文
	struct lws* websocket;  // WebSocket 连接
} funasr_recog_engine_t;

static apt_bool_t funasr_recog_msg_signal(funasr_recog_msg_type_e type, mrcp_engine_channel_t *channel, mrcp_message_t *request);
static apt_bool_t funasr_recog_msg_process(apt_task_t *task, apt_task_msg_t *msg);


/** Declare this macro to set plugin version */
MRCP_PLUGIN_VERSION_DECLARE

/**
 * Declare this macro to use log routine of the server, plugin is loaded from.
 * Enable/add the corresponding entry in logger.xml to set a cutsom log source priority.
 *    <source name="RECOG-PLUGIN" priority="DEBUG" masking="NONE"/>
 */
MRCP_PLUGIN_LOG_SOURCE_IMPLEMENT(RECOG_PLUGIN,"RECOG-PLUGIN")

/** Use custom log source mark */
#define RECOG_LOG_MARK   APT_LOG_MARK_DECLARE(RECOG_PLUGIN)

/** Create demo recognizer engine */
MRCP_PLUGIN_DECLARE(mrcp_engine_t*) mrcp_plugin_create(apr_pool_t *pool)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> mrcp_plugin_create");
	funasr_recog_engine_t *funasr_engine = apr_palloc(pool,sizeof(funasr_recog_engine_t));
	apt_task_t *task;
	apt_task_vtable_t *vtable;
	apt_task_msg_pool_t *msg_pool;

	//初始化websocket协议属性
	//initialize_protocols(); 


	// 创建哈希表，直接使用传入的 `pool`
	websocket_channel_map = apr_hash_make(pool);
	if (!websocket_channel_map) {
		apt_log(RECOG_LOG_MARK, APT_PRIO_WARNING, "Failed to create WebSocket channel map");
		return NULL;
	}

	msg_pool = apt_task_msg_pool_create_dynamic(sizeof(funasr_recog_msg_t),pool);
	funasr_engine->task = apt_consumer_task_create(funasr_engine,msg_pool,pool);
	if(!funasr_engine->task) {
		return NULL;
	}
	task = apt_consumer_task_base_get(funasr_engine->task);
	apt_task_name_set(task,RECOG_ENGINE_TASK_NAME);
	vtable = apt_task_vtable_get(task);
	if(vtable) {
		vtable->process_msg = funasr_recog_msg_process;
	}

	/* create engine base */
	return mrcp_engine_create(
				MRCP_RECOGNIZER_RESOURCE,  /* MRCP resource identifier */
				funasr_engine,               /* object to associate */
				&engine_vtable,            /* virtual methods table of engine */
				pool);                     /* pool to allocate memory from */
}

/** Destroy recognizer engine */
static apt_bool_t funasr_recog_engine_destroy(mrcp_engine_t *engine)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_engine_destroy");
	funasr_recog_engine_t *funasr_engine = engine->obj;
	if(funasr_engine->task) {
		apt_task_t *task = apt_consumer_task_base_get(funasr_engine->task);
		apt_task_destroy(task);
		funasr_engine->task = NULL;
	}
	return TRUE;
}

DWORD WINAPI websocket_event_loop(LPVOID lpParam) {
	struct lws_context* context = (struct lws_context*)lpParam;
	while (1) {
		lws_service(context, 100);  // 100毫秒超时
	}
	return 0;
}

/** Open recognizer engine */
static apt_bool_t funasr_recog_engine_open(mrcp_engine_t *engine)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_engine_open");
	funasr_recog_engine_t* funasr_engine = engine->obj;
	if (funasr_engine->task) {
		apt_task_t* task = apt_consumer_task_base_get(funasr_engine->task);
		apt_task_start(task);
	}
	struct lws_context_creation_info info;
	memset(&info, 0, sizeof(info));

	info.port = CONTEXT_PORT_NO_LISTEN; // 指定不监听任何端口
	info.protocols = protocols;        // 使用上面定义的协议
	info.gid = -1;
	info.uid = -1;

	funasr_engine->websocket_context = lws_create_context(&info);
	if (!funasr_engine->websocket_context) {
		apt_log(APT_LOG_MARK, APT_PRIO_WARNING, "Failed to create WebSocket context");
		return FALSE;
	}

	struct lws_client_connect_info connect_info = {
		.context = funasr_engine->websocket_context,
		.address = "localhost",          // 服务器地址
		.port = 10096,                    // 服务器端口
		.host = "127.0.0.1",
		.origin = "127.0.0.1",
		.protocol = protocols[0].name,   // 使用定义的协议名称
		.ssl_connection = 0              // SSL连接设置，根据需要调整
	};

	funasr_engine->websocket = lws_client_connect_via_info(&connect_info);
	if (!funasr_engine->websocket) {
		apt_log(APT_LOG_MARK, APT_PRIO_WARNING, "Failed to connect WebSocket");
		lws_context_destroy(funasr_engine->websocket_context);
		funasr_engine->websocket_context = NULL;
		return FALSE;
	}

	// 创建线程以非阻塞方式运行事件循环
	HANDLE threadHandle = CreateThread(NULL, 0, websocket_event_loop, funasr_engine->websocket_context, 0, NULL);
	if (threadHandle == NULL) {
		apt_log(APT_LOG_MARK, APT_PRIO_WARNING, "Failed to create WebSocket event loop thread");
		return FALSE;
	}
	CloseHandle(threadHandle);  // 立即关闭线程句柄，线程仍在后台运行

	return mrcp_engine_open_respond(engine, TRUE);
}


/** Close recognizer engine */
static apt_bool_t funasr_recog_engine_close(mrcp_engine_t *engine)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_engine_close");
	funasr_recog_engine_t *funasr_engine = engine->obj;
	if (funasr_engine->websocket_context) {
		lws_context_destroy(funasr_engine->websocket_context);
		funasr_engine->websocket_context = NULL;
	}
	return mrcp_engine_close_respond(engine);
}

static mrcp_engine_channel_t* funasr_recog_engine_channel_create(mrcp_engine_t *engine, apr_pool_t *pool)
{
	mpf_stream_capabilities_t *capabilities;
	mpf_termination_t *termination; 
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_engine_channel_create");
	
	/* create demo recog channel */
	funasr_recog_channel_t *recog_channel = apr_palloc(pool,sizeof(funasr_recog_channel_t));
	recog_channel->funasr_engine = engine->obj;
	recog_channel->recog_request = NULL;
	recog_channel->stop_response = NULL;
	recog_channel->detector = mpf_activity_detector_create(pool);
	recog_channel->audio_out = NULL;

	capabilities = mpf_sink_stream_capabilities_create(pool);
	mpf_codec_capabilities_add(
			&capabilities->codecs,
			MPF_SAMPLE_RATE_8000 | MPF_SAMPLE_RATE_16000,
			"LPCM");

	/* create media termination */
	termination = mrcp_engine_audio_termination_create(
			recog_channel,        /* object to associate */
			&audio_stream_vtable, /* virtual methods table of audio stream */
			capabilities,         /* stream capabilities */
			pool);                /* pool to allocate memory from */

	/* create engine channel base */
	recog_channel->channel = mrcp_engine_channel_create(
			engine,               /* engine */
			&channel_vtable,      /* virtual methods table of engine channel */
			recog_channel,        /* object to associate */
			termination,          /* associated media termination */
			pool);                /* pool to allocate memory from */
	/* 将channel和websocket放入缓存队列中*/

	// 生成一个 UUID
	char uuid_str[APR_UUID_FORMATTED_LENGTH + 1];
	apr_uuid_t uuid;
	apr_uuid_get(&uuid);
	apr_uuid_format(uuid_str, &uuid);
	recog_channel->uuid = apr_pstrdup(pool, uuid_str);
	apr_hash_set(websocket_channel_map, recog_channel->uuid, APR_HASH_KEY_STRING, recog_channel);
	apt_log(APT_LOG_MARK, APT_PRIO_INFO, "创建channel缓存的wav_name: %s", recog_channel->uuid);
	return recog_channel->channel;
}

/** Destroy engine channel */
static apt_bool_t funasr_recog_channel_destroy(mrcp_engine_channel_t *channel)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_channel_destroy");
	/* nothing to destrtoy */
	funasr_recog_channel_t* recog_channel = channel->method_obj;
	char* key = recog_channel->uuid;
	apr_hash_set(websocket_channel_map, key, APR_HASH_KEY_STRING, NULL);
	return TRUE;
}

/** Open engine channel (asynchronous response MUST be sent)*/
static apt_bool_t funasr_recog_channel_open(mrcp_engine_channel_t *channel)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_channel_open");
	if(channel->attribs) {
		/* process attributes */
		const apr_array_header_t *header = apr_table_elts(channel->attribs);
		apr_table_entry_t *entry = (apr_table_entry_t *)header->elts;
		int i;
		for(i=0; i<header->nelts; i++) {
			apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Attrib name [%s] value [%s]",entry[i].key,entry[i].val);
		}
	}
	return funasr_recog_msg_signal(FUNASR_RECOG_MSG_OPEN_CHANNEL,channel,NULL);
}

/** Close engine channel (asynchronous response MUST be sent)*/
static apt_bool_t funasr_recog_channel_close(mrcp_engine_channel_t *channel)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_channel_close");
	return funasr_recog_msg_signal(FUNASR_RECOG_MSG_CLOSE_CHANNEL,channel,NULL);
}

/** Process MRCP channel request (asynchronous response MUST be sent)*/
static apt_bool_t funasr_recog_channel_request_process(mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_channel_request_process");
	return funasr_recog_msg_signal(FUNASR_RECOG_MSG_REQUEST_PROCESS,channel,request);
}

/** Process RECOGNIZE request */
static apt_bool_t funasr_recog_channel_recognize(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	/* process RECOGNIZE request */
	mrcp_recog_header_t *recog_header;
	funasr_recog_channel_t *recog_channel = channel->method_obj;
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_channel_recognize");
	const mpf_codec_descriptor_t *descriptor = mrcp_engine_sink_stream_codec_get(channel);
	
	if(!descriptor) {
		apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Failed to Get Codec Descriptor " APT_SIDRES_FMT, MRCP_MESSAGE_SIDRES(request));
		response->start_line.status_code = MRCP_STATUS_CODE_METHOD_FAILED;
		return FALSE;
	}

	recog_channel->timers_started = TRUE;

	/* get recognizer header */
	recog_header = mrcp_resource_header_get(request);
	if(recog_header) {
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_START_INPUT_TIMERS) == TRUE) {
			recog_channel->timers_started = recog_header->start_input_timers;
		}
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_NO_INPUT_TIMEOUT) == TRUE) {
			mpf_activity_detector_noinput_timeout_set(recog_channel->detector,recog_header->no_input_timeout);
		}
		if(mrcp_resource_header_property_check(request,RECOGNIZER_HEADER_SPEECH_COMPLETE_TIMEOUT) == TRUE) {
			mpf_activity_detector_silence_timeout_set(recog_channel->detector,recog_header->speech_complete_timeout);
		}
	}

	if(!recog_channel->audio_out) {
		const apt_dir_layout_t *dir_layout = channel->engine->dir_layout;
		char *file_name = apr_psprintf(channel->pool,"utter-%dkHz-%s.pcm",
							descriptor->sampling_rate/1000,
							request->channel_id.session_id.buf);
		char *file_path = apt_vardir_filepath_get(dir_layout,file_name,channel->pool);
		if(file_path) {
			apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Open Utterance Output File [%s] for Writing",file_path);
			recog_channel->audio_out = fopen(file_path,"wb");
			if(!recog_channel->audio_out) {
				apt_log(RECOG_LOG_MARK,APT_PRIO_WARNING,"Failed to Open Utterance Output File [%s] for Writing",file_path);
			}
		}
	}

	response->start_line.request_state = MRCP_REQUEST_STATE_INPROGRESS;
	/* send asynchronous response */
	mrcp_engine_channel_message_send(channel,response);
	recog_channel->recog_request = request;
	return TRUE;
}

/** Process STOP request */
static apt_bool_t funasr_recog_channel_stop(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	
	/* process STOP request */
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_channel_stop");
	funasr_recog_channel_t *recog_channel = channel->method_obj;
	/* store STOP request, make sure there is no more activity and only then send the response */
	recog_channel->stop_response = response;
	return TRUE;
}

/** Process START-INPUT-TIMERS request */
static apt_bool_t funasr_recog_channel_timers_start(mrcp_engine_channel_t *channel, mrcp_message_t *request, mrcp_message_t *response)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_channel_timers_start");
	funasr_recog_channel_t *recog_channel = channel->method_obj;
	recog_channel->timers_started = TRUE;
	return mrcp_engine_channel_message_send(channel,response);
}

/** Dispatch MRCP request */
static apt_bool_t funasr_recog_channel_request_dispatch(mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	apt_bool_t processed = FALSE;
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_channel_request_dispatch");
	mrcp_message_t *response = mrcp_response_create(request,request->pool);
	switch(request->start_line.method_id) {
		case RECOGNIZER_SET_PARAMS:
			break;
		case RECOGNIZER_GET_PARAMS:
			break;
		case RECOGNIZER_DEFINE_GRAMMAR:
			break;
		case RECOGNIZER_RECOGNIZE:
			processed = funasr_recog_channel_recognize(channel,request,response);
			break;
		case RECOGNIZER_GET_RESULT:
			break;
		case RECOGNIZER_START_INPUT_TIMERS:
			processed = funasr_recog_channel_timers_start(channel,request,response);
			break;
		case RECOGNIZER_STOP:
			processed = funasr_recog_channel_stop(channel,request,response);
			break;
		default:
			break;
	}
	if(processed == FALSE) {
		/* send asynchronous response for not handled request */
		mrcp_engine_channel_message_send(channel,response);
	}
	return TRUE;
}

/** Callback is called from MPF engine context to destroy any additional data associated with audio stream */
static apt_bool_t funasr_recog_stream_destroy(mpf_audio_stream_t *stream)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_stream_destroy");
	return TRUE;
}

/** Callback is called from MPF engine context to perform any action before open */
static apt_bool_t funasr_recog_stream_open(mpf_audio_stream_t *stream, mpf_codec_t *codec)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_stream_open");
	return TRUE;
}

/** Callback is called from MPF engine context to perform any action after close */
static apt_bool_t funasr_recog_stream_close(mpf_audio_stream_t *stream)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_stream_close");
	return TRUE;
}

/* Raise demo START-OF-INPUT event */
static apt_bool_t funasr_recog_start_of_input(funasr_recog_channel_t *recog_channel)
{
	/* create START-OF-INPUT event */
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_start_of_input");
	mrcp_message_t *message = mrcp_event_create(
						recog_channel->recog_request,
						RECOGNIZER_START_OF_INPUT,
						recog_channel->recog_request->pool);
	if(!message) {
		return FALSE;
	}
	struct lws* wsi = recog_channel->funasr_engine->websocket;
	/* set request state */
	message->start_line.request_state = MRCP_REQUEST_STATE_INPROGRESS;
	/* 调用funasr 识别服务发送开始标志 JSON 消息 */
	size_t initial_msg_len = 0;
	unsigned char* initial_msg = NULL;
	const char* initial_msg_str = NULL;
	initial_msg = create_initial_json_message(&initial_msg_len, &initial_msg_str, recog_channel->uuid);
	apt_log(APT_LOG_MARK, APT_PRIO_INFO, "Sending initial message: %s\n", initial_msg_str);
	if (initial_msg != NULL) {
		lws_write(wsi, initial_msg + LWS_SEND_BUFFER_PRE_PADDING, initial_msg_len, LWS_WRITE_TEXT);
		free(initial_msg);
	}
	free((void*)initial_msg_str);
	/* send asynch event */

	return mrcp_engine_channel_message_send(recog_channel->channel,message);
}

/* Raise demo RECOGNITION-COMPLETE event */
static apt_bool_t funasr_recog_recognition_complete(funasr_recog_channel_t* recog_channel, mrcp_recog_completion_cause_e cause)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_recognition_complete");
	int result = 0;
	if (cause == RECOGNIZER_COMPLETION_CAUSE_SUCCESS) {
		struct lws* wsi = recog_channel->funasr_engine->websocket;
		/* 调用funasr 识别服务发送开始标志 JSON 消息 */
		size_t final_msg_len = 0;
		const char* final_msg_str = NULL;
		/* 一段话结束发送结束标志 JSON 消息 */
		unsigned char* final_msg = create_final_json_message(&final_msg_len, &final_msg_str);
		apt_log(APT_LOG_MARK, APT_PRIO_INFO, "Sending final message: %s\n", final_msg_str);
		if (final_msg != NULL) {
			result = lws_write(wsi, final_msg + LWS_SEND_BUFFER_PRE_PADDING, final_msg_len, LWS_WRITE_TEXT);
			free(final_msg);
		}
		free((void*)final_msg_str);
	}

	/* send asynch event */
	return result > 0;
}

/* Raise demo RECOGNITION-COMPLETE event */
static apt_bool_t funasr_recog_write(funasr_recog_channel_t* recog_channel, const mpf_frame_t* frame)
{
	struct lws* wsi = recog_channel->funasr_engine->websocket;
	size_t size = frame->codec_frame.size;
	const unsigned char* data = frame->codec_frame.buffer;
	unsigned char* buffer = malloc(LWS_SEND_BUFFER_PRE_PADDING + size + LWS_SEND_BUFFER_POST_PADDING);
	if (!buffer) {
		apt_log(RECOG_LOG_MARK, APT_PRIO_ERROR, "Failed to allocate memory for WebSocket write");
		return -1;
	} 
	memcpy(buffer + LWS_SEND_BUFFER_PRE_PADDING, data, size);
	int result = lws_write(wsi, buffer + LWS_SEND_BUFFER_PRE_PADDING, size, LWS_WRITE_BINARY);
	free(buffer);
	return result > 0;
}

/** Callback is called from MPF engine context to write/send new frame */
static apt_bool_t funasr_recog_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame)
{
	funasr_recog_channel_t *recog_channel = stream->obj;
	if(recog_channel->stop_response) {
		/* send asynchronous response to STOP request */
		mrcp_engine_channel_message_send(recog_channel->channel,recog_channel->stop_response);
		recog_channel->stop_response = NULL;
		recog_channel->recog_request = NULL;
		return TRUE;
	}

	if(recog_channel->recog_request) {
		mpf_detector_event_e det_event = mpf_activity_detector_process(recog_channel->detector,frame);
		/** 处理音频文件 **/
		switch(det_event) {
			case MPF_DETECTOR_EVENT_ACTIVITY:
				apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Voice Activity " APT_SIDRES_FMT,
					MRCP_MESSAGE_SIDRES(recog_channel->recog_request));
				funasr_recog_start_of_input(recog_channel);
				break;
			//case MPF_DETECTOR_EVENT_INACTIVITY:
			//	apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Voice Inactivity " APT_SIDRES_FMT,
			//		MRCP_MESSAGE_SIDRES(recog_channel->recog_request));
			//	funasr_recog_recognition_complete(recog_channel,RECOGNIZER_COMPLETION_CAUSE_SUCCESS);
			//	break;
			//case MPF_DETECTOR_EVENT_NOINPUT:
			//	apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Noinput " APT_SIDRES_FMT,
			//		MRCP_MESSAGE_SIDRES(recog_channel->recog_request));
			//	if(recog_channel->timers_started == TRUE) {
			//		funasr_recog_recognition_complete(recog_channel,RECOGNIZER_COMPLETION_CAUSE_NO_INPUT_TIMEOUT);
			//	}
			//	break;
			default:
				break;
		}
		funasr_recog_write(recog_channel, frame);

		if(recog_channel->recog_request) {
			if((frame->type & MEDIA_FRAME_TYPE_EVENT) == MEDIA_FRAME_TYPE_EVENT) {
				if(frame->marker == MPF_MARKER_START_OF_EVENT) {
					apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected Start of Event " APT_SIDRES_FMT " id:%d",
						MRCP_MESSAGE_SIDRES(recog_channel->recog_request),
						frame->event_frame.event_id);
				}
				else if(frame->marker == MPF_MARKER_END_OF_EVENT) {
					apt_log(RECOG_LOG_MARK,APT_PRIO_INFO,"Detected End of Event " APT_SIDRES_FMT " id:%d duration:%d ts",
						MRCP_MESSAGE_SIDRES(recog_channel->recog_request),
						frame->event_frame.event_id,
						frame->event_frame.duration);
				}
			}
		}
		//是否保存到音频文件
		if(recog_channel->audio_out) {
			fwrite(frame->codec_frame.buffer,1,frame->codec_frame.size,recog_channel->audio_out);
		}
	}
	return TRUE;
}

static apt_bool_t funasr_recog_msg_signal(funasr_recog_msg_type_e type, mrcp_engine_channel_t *channel, mrcp_message_t *request)
{
	apt_bool_t status = FALSE;
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_msg_signal");
	funasr_recog_channel_t *funasr_channel = channel->method_obj;
	funasr_recog_engine_t *funasr_engine = funasr_channel->funasr_engine;
	apt_task_t *task = apt_consumer_task_base_get(funasr_engine->task);
	apt_task_msg_t *msg = apt_task_msg_get(task);
	if(msg) {
		funasr_recog_msg_t *funasr_msg;
		msg->type = TASK_MSG_USER;
		funasr_msg = (funasr_recog_msg_t*) msg->data;

		funasr_msg->type = type;
		funasr_msg->channel = channel;
		funasr_msg->request = request;
		status = apt_task_msg_signal(task,msg);
	}
	return status;
}

static apt_bool_t funasr_recog_msg_process(apt_task_t *task, apt_task_msg_t *msg)
{
	apt_log(RECOG_LOG_MARK, APT_PRIO_DEBUG, "funasr method ==> funasr_recog_msg_process");
	funasr_recog_msg_t *funasr_msg = (funasr_recog_msg_t*)msg->data;
	switch(funasr_msg->type) {
		case FUNASR_RECOG_MSG_OPEN_CHANNEL:
			/* open channel and send asynch response */
			mrcp_engine_channel_open_respond(funasr_msg->channel,TRUE);
			break;
		case FUNASR_RECOG_MSG_CLOSE_CHANNEL:
		{
			/* close channel, make sure there is no activity and send asynch response */
			funasr_recog_channel_t *recog_channel = funasr_msg->channel->method_obj;
			if(recog_channel->audio_out) {
				fclose(recog_channel->audio_out);
				recog_channel->audio_out = NULL;
			}

			mrcp_engine_channel_close_respond(funasr_msg->channel);
			break;
		}
		case FUNASR_RECOG_MSG_REQUEST_PROCESS:
			funasr_recog_channel_request_dispatch(funasr_msg->channel,funasr_msg->request);
			break;
		default:
			break;
	}
	return TRUE;
}