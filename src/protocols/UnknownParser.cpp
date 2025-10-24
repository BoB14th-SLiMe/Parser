#include "UnknownParser.h"
#include <sstream>


// --- 추가: vtable 링커 오류 해결을 위한 명시적 소멸자 정의 ---
UnknownParser::~UnknownParser() {}

std::string UnknownParser::getName() const {
    return "unknown";
}

bool UnknownParser::isProtocol(const u_char* payload, int size) const {
    // This parser should be called last and handles any packet.
    return true;
}

void UnknownParser::parse(const PacketInfo& info) {
    std::stringstream details_ss;
    details_ss << "{\"len\":" << info.payload_size << "}";

    // --- 수정: "unknown" direction 전달 ---
    writeOutput(info, details_ss.str(), "unknown");
}
