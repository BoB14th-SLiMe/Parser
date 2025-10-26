#include "TcpSessionParser.h"

TcpSessionParser::TcpSessionParser() {}
TcpSessionParser::~TcpSessionParser() {}

std::string TcpSessionParser::getName() const {
    return "tcp_session";
}

// --- 수정: 'd' 필드에 들어갈 JSON 내용만 생성하여 반환 (비어 있음) ---
std::string TcpSessionParser::parse(uint32_t seq, uint32_t ack, uint8_t flags) const {
    // CSV에서는 이 'd' 컬럼이 아예 제외되므로, JSONL용으로 비어있는 객체만 반환
    return "{}";
}
