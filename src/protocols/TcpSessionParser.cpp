#include "TcpSessionParser.h"

TcpSessionParser::TcpSessionParser() {}
TcpSessionParser::~TcpSessionParser() {}

std::string TcpSessionParser::getName() const {
    return "tcp_session";
}

std::string TcpSessionParser::parse(uint32_t seq, uint32_t ack, uint8_t flags) const {
    std::stringstream ss;
    // Records seq, ack, and flags information in the 'd' object.
    ss << "{\"sq\":" << seq << ",\"ak\":" << ack << ",\"fl\":" << (int)flags << "}";
    return ss.str();
}

