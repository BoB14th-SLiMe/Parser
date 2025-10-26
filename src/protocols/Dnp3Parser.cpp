#include "Dnp3Parser.h"
#include <sstream>

// --- 추가: vtable 링커 오류 해결을 위한 명시적 소멸자 정의 ---
Dnp3Parser::~Dnp3Parser() {}

std::string Dnp3Parser::getName() const {
    return "dnp3";
}

bool Dnp3Parser::isProtocol(const u_char* payload, int size) const {
    // DNP3 Link Layer Start Bytes: 0x05 0x64
    return size >= 2 && payload[0] == 0x05 && payload[1] == 0x64;
}

void Dnp3Parser::parse(const PacketInfo& info) {
    std::stringstream details_ss;
    // --- 수정: direction 변수 추가 ---
    std::string direction = "unknown";

    if (info.payload_size >= 10) { // Minimum link layer header size
        uint8_t len = info.payload[2];
        uint8_t ctrl = info.payload[3];
        uint16_t dest = *(uint16_t*)(info.payload + 4);
        uint16_t src = *(uint16_t*)(info.payload + 6);
        
        // --- 수정: DNP3 Link Layer DIR bit로 direction 판단 ---
        // (ctrl & 0x80) -> DIR: 1 = Master to Outstation (request), 0 = Outstation to Master (response)
        direction = (ctrl & 0x80) ? "request" : "response";

        details_ss << "{\"len\":" << (int)len << ",\"ctrl\":" << (int)ctrl 
                   << ",\"dest\":" << dest << ",\"src\":" << src << "}";
    } else {
        details_ss << "{\"len\":" << info.payload_size << "}";
    }
    
    // --- 수정: direction 인자 전달 ---
    writeOutput(info, details_ss.str(), direction);
}

