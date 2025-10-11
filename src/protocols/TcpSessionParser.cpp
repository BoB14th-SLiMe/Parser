#include "TcpSessionParser.h"

TcpSessionParser::TcpSessionParser() {}
TcpSessionParser::~TcpSessionParser() {}

std::string TcpSessionParser::getName() const {
    return "tcp_session";
}

// --- 수정: 'd' 필드에 들어갈 JSON 내용만 생성하여 반환 ---
std::string TcpSessionParser::parse(uint32_t seq, uint32_t ack, uint8_t flags) const {
    std::stringstream details_ss;
    // sq, ak, fl 정보는 상위 레벨에 이미 존재하므로, d 필드에는 추가 정보를 넣거나 비워둘 수 있습니다.
    // 여기서는 일관성을 위해 비워두겠습니다.
    details_ss << "{}";
    return details_ss.str();
}

