# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

include_directories(src/main/cpp/include)

add_library(
        apm-plugin-packet-processing
        SHARED
        src/main/cpp/packet_processing_plugin_jni.cpp
)

add_library(openssl-crypto
        STATIC
        IMPORTED)

set_target_properties(
        openssl-crypto
        PROPERTIES IMPORTED_LOCATION
        "${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libcrypto.a")

add_library(openssl-ssl
        STATIC
        IMPORTED)

set_target_properties(
        openssl-ssl
        PROPERTIES IMPORTED_LOCATION
        "${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libssl.a")

find_library(log-lib log)

target_link_libraries(
        apm-plugin-packet-processing
        openssl-crypto
        openssl-ssl
        ${log-lib}
        )