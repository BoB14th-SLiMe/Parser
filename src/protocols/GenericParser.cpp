#include "GenericParser.h"
#include <sstream>
#include <cstring> // For memcmp

GenericParser::GenericParser(const std::string& name) : m_name(name) {}
GenericParser::~GenericParser() {}

std::string GenericParser::getName() const {
    return m_name;
}

bool GenericParser::isProtocol(const u_char* payload, int size) const {
    // 각 프로토콜의 시그니처를 여기서 확인
    if (m_name == "ethernet_ip") {
        return size >= 24; // 매우 기본적인 확인
    }
    if (m_name == "iec104") {
        return size >= 2 && payload[0] == 0x68;
    }
    if (m_name == "mms") {
        // TPKT(0x03), COTP 기반이지만 S7(0x32)이 아닌 경우
        return size > 8 && payload[0] == 0x03 && payload[5] != 0xf0 && payload[7] != 0x32;
    }
    if (m_name == "opc_ua") {
        // "OPC"는 OPC-DA Classic. UA는 보통 "HELO" 메시지로 시작
        return size >= 4 && memcmp(payload, "HELO", 4) == 0;
    }
    if (m_name == "bacnet") {
        // BACnet/IP (Annex J)
        return size >= 4 && payload[0] == 0x81 && (payload[1] == 0x0a || payload[1] == 0x0b);
    }
    if (m_name == "dhcp") {
        if (size < 240) return false;
        // Magic cookie 0x63825363
        return payload[236] == 0x63 && payload[237] == 0x82 && payload[238] == 0x53 && payload[239] == 0x63;
    }
    return false;
}

void GenericParser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;

    std::stringstream details_ss;
    details_ss << "{\"len\":" << info.payload_size << "}";

    *m_output_stream << info.timestamp // "{\"ts\":\"...\"" 또는 "{\"td\":...}"
                   << "\"sip\":\"" << info.src_ip << "\",\"sp\":" << info.src_port << ","
                   << "\"dip\":\"" << info.dst_ip << "\",\"dp\":" << info.dst_port << ","
                   << "\"sq\":" << info.tcp_seq << ",\"ak\":" << info.tcp_ack << ",\"fl\":" << (int)info.tcp_flags << ","
                   << "\"d\":" << details_ss.str() << "}\n";
}

void GenericParser::setOutputStream(std::ofstream* stream) {
    m_output_stream = stream;
}
