#include "ArpParser.h"
#include "../UnifiedWriter.h"
#include "../network/network_headers.h"
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

ArpParser::ArpParser() {}
ArpParser::~ArpParser() {}

std::string ArpParser::getName() const {
    return "arp";
}

bool ArpParser::isProtocol(const PacketInfo& info) const {
    return info.eth_type == 0x0806;
}

void ArpParser::parse(const PacketInfo& info) {
    // size_t로 캐스팅하여 signed/unsigned 비교 경고 제거
    if (static_cast<size_t>(info.payload_size) < sizeof(ARPHeader)) return;

    const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(info.payload);

    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (void*)arp_header->spa, spa_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (void*)arp_header->tpa, tpa_str, INET_ADDRSTRLEN);

    uint16_t op_code = ntohs(arp_header->oper);
    std::string sha_str = mac_to_string(arp_header->sha);
    std::string tha_str = mac_to_string(arp_header->tha);

    std::string direction = (op_code == 1) ? "request" : (op_code == 2 ? "response" : "other");

    UnifiedRecord record = createUnifiedRecord(info, direction);

    // Set payload length (common field for all protocols)
    record.len = std::to_string(info.payload_size);

    record.arp_op = std::to_string(op_code);
    record.arp_tmac = tha_str;
    record.arp_tip = tpa_str;
    
    std::stringstream details_ss;
    details_ss << R"({"op":)" << op_code 
               << R"(,"smac":")" << sha_str << R"(",)"
               << R"("sip":")" << spa_str << R"(",)"
               << R"("tmac":")" << tha_str << R"(",)"
               << R"("tip":")" << tpa_str << R"("})";
    record.details_json = details_ss.str();
    
    addUnifiedRecord(record);
}