cmake_minimum_required(VERSION 3.10)
project(RealtimeParser)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 필수 패키지 찾기
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPCAP REQUIRED libpcap)
pkg_check_modules(HIREDIS REQUIRED hiredis)
find_package(CURL REQUIRED)

# nlohmann/json 다운로드
include(FetchContent)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(json)

# 소스 파일들
set(SOURCES
    src/main.cpp
    src/PacketParser.cpp
    src/AssetManager.cpp
    src/RedisCache.cpp
    src/ElasticsearchClient.cpp
    src/TimeBasedCsvWriter.cpp
    
    # Protocol parsers
    src/protocols/IProtocolParser.cpp
    src/protocols/BaseProtocolParser.cpp
    src/protocols/ArpParser.cpp
    src/protocols/TcpSessionParser.cpp
    src/protocols/ModbusParser.cpp
    src/protocols/S7CommParser.cpp
    src/protocols/XgtFenParser.cpp
    src/protocols/Dnp3Parser.cpp
    src/protocols/DnsParser.cpp
    src/protocols/GenericParser.cpp
    src/protocols/UnknownParser.cpp
)

# 헤더 파일들
set(HEADERS
    src/PacketParser.h
    src/AssetManager.h
    src/RedisCache.h
    src/ElasticsearchClient.h
    src/TimeBasedCsvWriter.h
    src/network/network_headers.h
    
    # Protocol parser headers
    src/protocols/IProtocolParser.h
    src/protocols/BaseProtocolParser.h
    src/protocols/ArpParser.h
    src/protocols/TcpSessionParser.h
    src/protocols/ModbusParser.h
    src/protocols/S7CommParser.h
    src/protocols/XgtFenParser.h
    src/protocols/Dnp3Parser.h
    src/protocols/DnsParser.h
    src/protocols/GenericParser.h
    src/protocols/UnknownParser.h
)

# 실행 파일 생성
add_executable(parser ${SOURCES} ${HEADERS})

# 컴파일 옵션
target_compile_options(parser PRIVATE
    -Wall
    -Wextra
    -O2
)

# 링크 옵션
target_link_options(parser PRIVATE
    -pthread
)

# Include 디렉토리
target_include_directories(parser PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${LIBPCAP_INCLUDE_DIRS}
    ${HIREDIS_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

# 라이브러리 링크
target_link_libraries(parser
    nlohmann_json::nlohmann_json
    ${LIBPCAP_LIBRARIES}
    ${HIREDIS_LIBRARIES}
    ${CURL_LIBRARIES}
    pthread
)

# 설치 규칙
install(TARGETS parser
    RUNTIME DESTINATION bin
)

# 디버그 메시지
message(STATUS "libpcap: ${LIBPCAP_LIBRARIES}")
message(STATUS "hiredis: ${HIREDIS_LIBRARIES}")
message(STATUS "curl: ${CURL_LIBRARIES}")