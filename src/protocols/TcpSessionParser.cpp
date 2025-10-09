#include "TcpSessionParser.h"

TcpSessionParser::TcpSessionParser() {}
TcpSessionParser::~TcpSessionParser() {}

std::string TcpSessionParser::getName() const {
    return "tcp_session";
}

std::string TcpSessionParser::parse(uint32_t seq, uint32_t ack, uint8_t flags) const {
    std::stringstream ss;
    // seq, ack, flags 정보를 'd' 객체에 기록합니다.
    ss << "{\"sq\":" << seq << ",\"ak\":" << ack << ",\"fl\":" << (int)flags << "}";
    return ss.str();
}
