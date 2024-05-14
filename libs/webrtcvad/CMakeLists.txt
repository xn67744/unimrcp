cmake_minimum_required(VERSION 2.8)
project(vad)

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}/webrtc
    ${PROJECT_SOURCE_DIR}/webrtc/common_audio/signal_processing/include
    ${PROJECT_SOURCE_DIR}/webrtc/common_audio/vad/include
    ${PROJECT_SOURCE_DIR}/webrtc/system_wrappers/interface
)

# Set header files
set(VAD_HEADERS
    webrtc/typedefs.h
    webrtc/common_audio/signal_processing/include/signal_processing_library.h
    webrtc/common_audio/signal_processing/include/spl_inl.h
    webrtc/common_audio/vad/vad_core.h
    webrtc/common_audio/vad/vad_filterbank.h
    webrtc/common_audio/vad/vad_gmm.h
    webrtc/common_audio/vad/vad_sp.h
    webrtc/common_audio/vad/include/webrtc_vad.h
    webrtc/system_wrappers/interface/cpu_features_wrapper.h
	webrtc/common_audio/signal_processing/complex_fft_tables.h
	webrtc/common_audio/signal_processing/resample_by_2_internal.h
)

# Set source files
set(VAD_SOURCES
    webrtc/common_audio/signal_processing/complex_bit_reverse.c
    webrtc/common_audio/signal_processing/complex_fft.c
    webrtc/common_audio/signal_processing/cross_correlation.c
    webrtc/common_audio/signal_processing/division_operations.c
    webrtc/common_audio/signal_processing/downsample_fast.c
    webrtc/common_audio/signal_processing/energy.c
    webrtc/common_audio/signal_processing/get_scaling_square.c
    webrtc/common_audio/signal_processing/min_max_operations.c
    webrtc/common_audio/signal_processing/real_fft.c
    webrtc/common_audio/signal_processing/resample_48khz.c
    webrtc/common_audio/signal_processing/resample_by_2_internal.c
    webrtc/common_audio/signal_processing/resample_fractional.c
    webrtc/common_audio/signal_processing/spl_init.c
    webrtc/common_audio/signal_processing/vector_scaling_operations.c
    webrtc/common_audio/vad/vad_core.c
    webrtc/common_audio/vad/vad_filterbank.c
    webrtc/common_audio/vad/vad_gmm.c
    webrtc/common_audio/vad/vad_sp.c
    webrtc/common_audio/vad/webrtc_vad.c
)

# Library declaration
add_library(vad STATIC ${VAD_SOURCES} ${VAD_HEADERS})

# Set target properties
set_target_properties(vad PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    FOLDER "libs"
)

# Preprocessor definitions
if (MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MTd")
    else ()
        set(CMAKE_BUILD_TYPE "Release")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT /fp:fast /Gy /Oi /Oy /O2 /Ot /Zi /EHsc")
    endif ()
else ()
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall -Wno-unused-variable")
    else ()
        set(CMAKE_BUILD_TYPE "Release")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O2")
    endif ()
endif ()