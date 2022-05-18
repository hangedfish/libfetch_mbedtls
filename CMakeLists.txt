cmake_minimum_required(VERSION 3.16)
project(fetch_cxx)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)
FetchContent_Declare(
        mbedtls
        URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.1.0.tar.gz
)
FetchContent_MakeAvailable(mbedtls)

set(ENABLE_SSL ON)
add_definitions(-DCA_CERT_FILE="${CMAKE_CURRENT_SOURCE_DIR}/DigiCertGlobalRootCA.crt.pem")

add_subdirectory(libfetch)
target_link_libraries(
        fetch
        mbedtls
)

add_executable(
        fetch_cxx
        main.cpp
)

target_link_libraries(
        fetch_cxx
        fetch
)