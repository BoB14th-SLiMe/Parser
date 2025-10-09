# CMake 최소 요구 버전
cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름 설정
project(PacketParser C CXX)

# --- macOS 환경에서 컴파일러를 명시적으로 지정 ---
# CMake가 링커(ld)를 직접 호출하는 문제를 방지하고,
# clang++ 드라이버를 통해 링크하도록 강제합니다.
if(APPLE)
    set(CMAKE_C_COMPILER "clang")
    set(CMAKE_CXX_COMPILER "clang++")
endif()

# C++ 표준 설정
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 'parser'라는 이름의 실행 파일 생성
add_executable(parser
    src/main.cpp
    src/PacketParser.cpp
    src/protocols/ModbusParser.cpp
    src/protocols/S7CommParser.cpp
    src/protocols/IProtocolParser.cpp
)

# --- pcap 라이브러리 수동으로 찾기 ---
find_path(PCAP_INCLUDE_DIR pcap.h HINTS /opt/homebrew/include)
find_library(PCAP_LIBRARY NAMES pcap HINTS /opt/homebrew/lib)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "Could not find pcap library. Please install libpcap-dev or equivalent.")
endif()

# --- 헤더 파일 검색 경로 추가 ---
# 1. 우리 프로젝트의 'include' 폴더를 검색 경로에 추가합니다.
# 2. pcap 라이브러리의 헤더 폴더를 검색 경로에 추가합니다.
target_include_directories(parser PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    ${PCAP_INCLUDE_DIR}
)

# 생성된 실행 파일에 pcap 라이브러리를 연결(링크)합니다.
target_link_libraries(parser PRIVATE ${PCAP_LIBRARY})
