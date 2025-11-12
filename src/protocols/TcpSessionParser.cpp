#include "TcpSessionParser.h"
#include "../UnifiedWriter.h"
#include "../network/network_headers.h"
#include <sstream>

TcpSessionParser::TcpSessionParser() {}
TcpSessionParser::~TcpSessionParser() {}

std::string TcpSessionParser::getName() const {
    return "tcp_session";
}

bool TcpSessionParser::isProtocol(const PacketInfo& info) const {
    (void)info;  // 경고 제거
    return true;
}

void TcpSessionParser::parse(const PacketInfo& info) {
    UnifiedRecord record = createUnifiedRecord(info, "unknown");

    // Set payload length (common field for all protocols)
    record.len = std::to_string(info.payload_size);

    std::stringstream details_ss;
    details_ss << R"({"seq":)" << info.tcp_seq << R"(,"ack":)" << info.tcp_ack
               << R"(,"flags":{"syn":)" << ((info.tcp_flags & TH_SYN) ? 1 : 0)
               << R"(,"ack":)" << ((info.tcp_flags & TH_ACK) ? 1 : 0)
               << R"(,"fin":)" << ((info.tcp_flags & TH_FIN) ? 1 : 0)
               << R"(,"rst":)" << ((info.tcp_flags & TH_RST) ? 1 : 0) << "}}";
    record.details_json = details_ss.str();

    addUnifiedRecord(record);
}