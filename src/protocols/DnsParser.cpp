#include "DnsParser.h"
#include <sstream>
#include <arpa/inet.h>

DnsParser::~DnsParser() {}

std::string DnsParser::getName() const {
    return "dns";
}

bool DnsParser::isProtocol(const u_char* payload, int size) const {
    // DNS는 보통 UDP 53번 포트를 사용하며, 최소 헤더 크기는 12바이트
    return size >= 12;
}

void DnsParser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;

    std::stringstream details_ss;
    if (info.payload_size >= 12) {
        uint16_t tid = ntohs(*(uint16_t*)(info.payload));
        uint16_t flags = ntohs(*(uint16_t*)(info.payload + 2));
        uint16_t qdcount = ntohs(*(uint16_t*)(info.payload + 4)); // Question count
        uint16_t ancount = ntohs(*(uint16_t*)(info.payload + 6)); // Answer count
        details_ss << "{\"tid\":" << tid << ",\"fl\":" << flags
                   << ",\"qc\":" << qdcount << ",\"ac\":" << ancount << "}";
    } else {
        details_ss << "{\"len\":" << info.payload_size << "}";
    }

    *m_output_stream << info.timestamp
                   << "\"sip\":\"" << info.src_ip << "\",\"sp\":" << info.src_port << ","
                   << "\"dip\":\"" << info.dst_ip << "\",\"dp\":" << info.dst_port << ","
                   << "\"sq\":" << info.tcp_seq << ",\"ak\":" << info.tcp_ack << ",\"fl\":" << (int)info.tcp_flags << ","
                   << "\"d\":" << details_ss.str() << "}\n";
}

void DnsParser::setOutputStream(std::ofstream* stream) {
    m_output_stream = stream;
}
