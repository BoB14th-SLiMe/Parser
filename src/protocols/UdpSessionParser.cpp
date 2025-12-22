#include "UdpSessionParser.h"
#include "../UnifiedWriter.h"
#include "../network/network_headers.h"
#include <sstream>

UdpSessionParser::UdpSessionParser() {}
UdpSessionParser::~UdpSessionParser() {}

std::string UdpSessionParser::getName() const {
    return "udp";  // Python과 일치
}

bool UdpSessionParser::isProtocol(const PacketInfo& info) const {
    // UDP 프로토콜만 처리 (Python과 일치)
    return (info.protocol == 17);  // IPPROTO_UDP
}

void UdpSessionParser::parse(const PacketInfo& info) {
    UnifiedRecord record = createUnifiedRecord(info, "unknown");

    // Set len to 0 for UDP packets (to match wireshark_parser)
    record.len = "0";

    addUnifiedRecord(record);
}
