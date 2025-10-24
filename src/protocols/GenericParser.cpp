#include "GenericParser.h"
#include <sstream>
#include <cstring> // For memcmp

// --- 추가: vtable 링커 오류 해결을 위한 명시적 소멸자 정의 ---
GenericParser::~GenericParser() {}

GenericParser::GenericParser(const std::string& name) : m_name(name) {}

std::string GenericParser::getName() const {
    return m_name;
}

bool GenericParser::isProtocol(const u_char* payload, int size) const {
    if (m_name == "ethernet_ip") {
        return size >= 24;
    }
    if (m_name == "iec104") {
        return size >= 2 && payload[0] == 0x68;
    }
    if (m_name == "mms") {
        return size > 8 && payload[0] == 0x03 && payload[5] != 0xf0 && payload[7] != 0x32;
    }
    if (m_name == "opc_ua") {
        return size >= 4 && memcmp(payload, "HELO", 4) == 0;
    }
    if (m_name == "bacnet") {
        return size >= 4 && payload[0] == 0x81 && (payload[1] == 0x0a || payload[1] == 0x0b);
    }
    if (m_name == "dhcp") {
        if (size < 240) return false;
        return payload[236] == 0x63 && payload[237] == 0x82 && payload[238] == 0x53 && payload[239] == 0x63;
    }
    return false;
}

void GenericParser::parse(const PacketInfo& info) {
    std::stringstream details_ss;
    details_ss << "{\"len\":" << info.payload_size << "}";

    // --- 수정: "unknown" direction 전달 ---
    writeOutput(info, details_ss.str(), "unknown");
}
