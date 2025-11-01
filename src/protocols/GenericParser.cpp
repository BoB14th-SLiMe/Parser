#include "GenericParser.h"
#include <sstream>
#include <cstring> // For memcmp
#include <string> // for std::to_string
#include <iostream> // For std::cout (debugging)

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


bool GenericParser::isProtocol(const PacketInfo& info) const {
    if (info.protocol == IPPROTO_TCP) {
        if (m_name == "ethernet_ip") {
            return info.src_port == 44818 || info.dst_port == 44818;
        }
        if (m_name == "iec104") {
            return info.src_port == 2404 || info.dst_port == 2404;
        }
        if (m_name == "mms") {
            return info.src_port == 102 || info.dst_port == 102;
        }
        if (m_name == "opc_ua") {
            return info.src_port == 4840 || info.dst_port == 4840;
        }
    }
    else if (info.protocol == IPPROTO_UDP) {
        if (m_name == "dhcp") {
                if (m_name == "dhcp") {
                return info.src_port == 67 || info.dst_port == 67 || info.src_port == 68 || info.dst_port == 68;
            }
            }
        if (m_name == "bacnet") {
            return info.src_port == 47808 || info.dst_port == 47808;
        }
    }
    return false;
}

void GenericParser::parse(const PacketInfo& info) {
    std::stringstream details_ss_json;
    details_ss_json << "{\"len\":" << info.payload_size << "}";
    std::string direction = "";
    if (info.src_port == 67 || info.src_port == 68) direction = "client_to_server";
    else if (info.dst_port == 67 || info.dst_port == 68) direction = "server_to_client";
    else direction = "unknown";

    // --- 1. JSONL 파일 쓰기 (기존 'd' 구조 유지) ---
    if (m_json_stream && m_json_stream->is_open()) {
        writeJsonl(info, direction, details_ss_json.str());
    }

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
