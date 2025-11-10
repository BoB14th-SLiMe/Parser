cmake_minimum_required(VERSION 3.10)
project(ICSPacketParser)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Find libcurl for Elasticsearch
find_package(CURL REQUIRED)

# Find hiredis for Redis
pkg_check_modules(HIREDIS REQUIRED hiredis)

# nlohmann_json (header-only library)
find_package(nlohmann_json 3.2.0 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${PCAP_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${HIREDIS_INCLUDE_DIRS}
)

# Source files
set(PROTOCOL_SOURCES
    src/protocols/IProtocolParser.cpp
    src/protocols/BaseProtocolParser.cpp
    src/protocols/ModbusParser.cpp
    src/protocols/S7CommParser.cpp
    src/protocols/XgtFenParser.cpp
    src/protocols/Dnp3Parser.cpp
    src/protocols/DnsParser.cpp
    src/protocols/GenericParser.cpp
    src/protocols/UnknownParser.cpp
    src/protocols/ArpParser.cpp
    src/protocols/TcpSessionParser.cpp
)

set(CORE_SOURCES
    src/AssetManager.cpp
    src/PacketParser.cpp
    src/UnifiedWriter.cpp
    src/TimeBasedCsvWriter.cpp
    src/RedisCache.cpp              # 추가
    src/ElasticsearchClient.cpp     # 추가
)

set(MAIN_SOURCE
    src/main.cpp
)

# Executable
add_executable(parser
    ${MAIN_SOURCE}
    ${CORE_SOURCES}
    ${PROTOCOL_SOURCES}
)

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wunused
)

# 디버그 빌드에서 주소 새니타이저 활성화
if(CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

# Link libraries
target_link_libraries(parser
    ${PCAP_LIBRARIES}
    ${CURL_LIBRARIES}              # 추가
    ${HIREDIS_LIBRARIES}           # 추가
    nlohmann_json::nlohmann_json
    pthread
)

# Compiler flags
target_compile_options(parser PRIVATE
    -Wall
    -Wextra
    -O3
    -march=native
)

# Installation
install(TARGETS parser DESTINATION bin)

# Print configuration
message(STATUS "PCAP include dirs: ${PCAP_INCLUDE_DIRS}")
message(STATUS "PCAP libraries: ${PCAP_LIBRARIES}")
message(STATUS "CURL include dirs: ${CURL_INCLUDE_DIRS}")
message(STATUS "CURL libraries: ${CURL_LIBRARIES}")
message(STATUS "HIREDIS include dirs: ${HIREDIS_INCLUDE_DIRS}")
message(STATUS "HIREDIS libraries: ${HIREDIS_LIBRARIES}")