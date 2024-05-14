#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <libwebsockets.h>
#include <json-c/json.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// 线程参数
struct ws_send_thread_params {
    struct lws* wsi;
};

// 构建初始 JSON 消息
static unsigned char* create_initial_json_message(size_t* out_size, const char** out_str) {
    json_object* json_msg = json_object_new_object();
    json_object_object_add(json_msg, "mode", json_object_new_string("2pass"));
    json_object_object_add(json_msg, "wav_name", json_object_new_string("utter-8kHz-447eeb38e811644c"));
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

// 构建最终 JSON 消息
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

// 发送消息和文件的线程函数
static DWORD WINAPI ws_send_thread(LPVOID param) {
    struct ws_send_thread_params* thread_params = (struct ws_send_thread_params*)param;
    struct lws* wsi = thread_params->wsi;

    size_t initial_msg_len = 0, final_msg_len = 0;
    unsigned char* initial_msg = NULL, * final_msg = NULL;
    const char* initial_msg_str = NULL, * final_msg_str = NULL;

    // 发送初始 JSON 消息
    initial_msg = create_initial_json_message(&initial_msg_len, &initial_msg_str);
    printf("Sending initial message: %s\n", initial_msg_str);
    if (initial_msg != NULL) {
        lws_write(wsi, initial_msg + LWS_SEND_BUFFER_PRE_PADDING, initial_msg_len, LWS_WRITE_TEXT);
        free(initial_msg);
    }
    free((void*)initial_msg_str);

    // 打开音频文件
    FILE* file;
    errno_t err = fopen_s(&file, "D:\\codes\\workspace-c++\\unimrcp\\unimrcp-1.8.0\\Debug\\var\\utter-8kHz-447eeb38e811644c.pcm", "rb");
    if (err != 0 || file == NULL) {
        perror("Failed to open file");
        return -1;
    }

    // 跳过 wav 文件头（如果有）
    fseek(file, 44, SEEK_SET);

    // 定义音频块大小
    const size_t chunk_size = 1920;
    unsigned char* chunk_buffer = (unsigned char*)malloc(LWS_SEND_BUFFER_PRE_PADDING + chunk_size + LWS_SEND_BUFFER_POST_PADDING);
    if (chunk_buffer == NULL) {
        perror("Failed to allocate chunk buffer");
        fclose(file);
        return -1;
    }

    // 持续发送音频数据
    size_t read_size;
    while ((read_size = fread(chunk_buffer + LWS_SEND_BUFFER_PRE_PADDING, 1, chunk_size, file)) > 0) {
        lws_write(wsi, chunk_buffer + LWS_SEND_BUFFER_PRE_PADDING, read_size, LWS_WRITE_BINARY);
        Sleep(60);  // 模拟在线传输的延迟
    }

    free(chunk_buffer);
    fclose(file);

    // 发送结束标志 JSON 消息
    final_msg = create_final_json_message(&final_msg_len, &final_msg_str);
    printf("Sending final message: %s\n", final_msg_str);
    if (final_msg != NULL) {
        lws_write(wsi, final_msg + LWS_SEND_BUFFER_PRE_PADDING, final_msg_len, LWS_WRITE_TEXT);
        free(final_msg);
    }
    free((void*)final_msg_str);

    return 0;
}

// WebSocket 回调事件处理函数
static int callback_websockets(struct lws* wsi, enum lws_callback_reasons reason,
    void* user, void* in, size_t len) {
    static struct ws_send_thread_params thread_params;
    static HANDLE thread_handle = NULL;

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        printf("Connection established\n");

        // 启动音频发送线程
        thread_params.wsi = wsi;
        thread_handle = CreateThread(NULL, 0, ws_send_thread, &thread_params, 0, NULL);
        if (thread_handle == NULL) {
            printf("Failed to create send thread\n");
        }

        break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
        // 接收消息
        printf("Received data: %.*s\n", (int)len, (char*)in);
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        printf("Connection failed\n");
        break;

    case LWS_CALLBACK_CLIENT_CLOSED:
        printf("Connection closed\n");
        if (thread_handle != NULL) {
            WaitForSingleObject(thread_handle, INFINITE);
            CloseHandle(thread_handle);
            thread_handle = NULL;
        }
        break;

    default:
        break;
    }

    return 0;
}

// 定义 WebSocket 协议
static struct lws_protocols protocols[] = {
    {
        "default",  // 协议名称
        callback_websockets,   // 回调函数
        0,  // per_session_data_size
        0,  // max rx buffer
    },
    { NULL, NULL, 0, 0 } // 结束标记
};

int main() {
    SetConsoleOutputCP(65001);
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;

    struct lws_context* context = lws_create_context(&info);
    if (context == NULL) {
        fprintf(stderr, "lws init failed\n");
        return -1;
    }

    struct lws_client_connect_info connect_info = { 0 };
    connect_info.context = context;
    connect_info.address = "127.0.0.1";  // WebSocket 服务器地址
    connect_info.port = 10096;           // 服务器端口
    connect_info.host = connect_info.address;
    connect_info.origin = connect_info.address;
    connect_info.protocol = protocols[0].name;
    connect_info.ssl_connection = 0;     // 不使用 SSL

    struct lws* wsi = lws_client_connect_via_info(&connect_info);
    if (wsi == NULL) {
        fprintf(stderr, "Connection failed\n");
        lws_context_destroy(context);
        return -1;
    }

    while (1) {
        lws_service(context, 100);
    }

    lws_context_destroy(context);
    return 0;
}
