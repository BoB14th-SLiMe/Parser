#include "UnknownParser.h"
#include <sstream>

UnknownParser::~UnknownParser() {}

std::string UnknownParser::getName() const {
    return "unknown";
}

bool UnknownParser::isProtocol(const u_char* payload, int size) const {
    // 이 파서는 항상 마지막에 호출되어야 하며, 모든 패킷을 처리합니다.
    return true;
}

void UnknownParser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;

    std::stringstream details_ss;
    details_ss << "{\"len\":" << info.payload_size << "}";

    *m_output_stream << info.timestamp
                   << "\"sip\":\"" << info.src_ip << "\",\"sp\":" << info.src_port << ","
                   << "\"dip\":\"" << info.dst_ip << "\",\"dp\":" << info.dst_port << ","
                   << "\"sq\":" << info.tcp_seq << ",\"ak\":" << info.tcp_ack << ",\"fl\":" << (int)info.tcp_flags << ","
                   << "\"d\":" << details_ss.str() << "}\n";
}

void UnknownParser::setOutputStream(std::ofstream* stream) {
    m_output_stream = stream;
}
