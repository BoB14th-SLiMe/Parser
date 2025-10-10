#include "Dnp3Parser.h"
#include <sstream>

Dnp3Parser::~Dnp3Parser() {}

std::string Dnp3Parser::getName() const {
    return "dnp3";
}

bool Dnp3Parser::isProtocol(const u_char* payload, int size) const {
    // DNP3 Link Layer Start Bytes: 0x05 0x64
    return size >= 2 && payload[0] == 0x05 && payload[1] == 0x64;
}

void Dnp3Parser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;

    std::stringstream details_ss;
    if (info.payload_size >= 10) { // 최소 링크 계층 헤더 크기
        uint8_t len = info.payload[2];
        uint8_t ctrl = info.payload[3];
        uint16_t dest = *(uint16_t*)(info.payload + 4);
        uint16_t src = *(uint16_t*)(info.payload + 6);
        details_ss << "{\"len\":" << (int)len << ",\"ctrl\":" << (int)ctrl 
                   << ",\"dest\":" << dest << ",\"src\":" << src << "}";
    } else {
        details_ss << "{\"len\":" << info.payload_size << "}";
    }

    *m_output_stream << "{\"@timestamp\":\"" << info.timestamp << "\","
                   << "\"sip\":\"" << info.src_ip << "\",\"sp\":" << info.src_port << ","
                   << "\"dip\":\"" << info.dst_ip << "\",\"dp\":" << info.dst_port << ","
                   << "\"sq\":" << info.tcp_seq << ",\"ak\":" << info.tcp_ack << ",\"fl\":" << (int)info.tcp_flags << ","
                   << "\"d\":" << details_ss.str() << "}\n";
}

void Dnp3Parser::setOutputStream(std::ofstream* stream) {
    m_output_stream = stream;
}
