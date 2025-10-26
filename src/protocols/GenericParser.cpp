#include "GenericParser.h"
#include <sstream>
#include <cstring> // For memcmp
#include <string> // for std::to_string

GenericParser::~GenericParser() {}

GenericParser::GenericParser(const std::string& name) : m_name(name) {}

std::string GenericParser::getName() const {
    return m_name;
}

// --- 추가: Generic/Unknown 파서용 CSV 헤더 (len 컬럼만 추가) ---
void GenericParser::writeCsvHeader(std::ofstream& csv_stream) {
    // dhcp, ethernet_ip, iec104, mms, opc_ua, bacnet
    // 모두 'len' 필드만 파싱하므로, 'len' 컬럼만 추가합니다.
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,len\n";
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
    std::stringstream details_ss_json;
    details_ss_json << "{\"len\":" << info.payload_size << "}";
    std::string direction = "unknown";

    // --- 1. JSONL 파일 쓰기 (기존 'd' 구조 유지) ---
    writeJsonl(info, direction, details_ss_json.str());

    // --- 2. CSV 파일 쓰기 (정규화된(flattened) 컬럼) ---
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                      << direction << ","
                      << info.payload_size << "\n"; // 'len' 컬럼
    }
}
