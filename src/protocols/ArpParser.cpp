#include "ArpParser.h"
#include "../network/network_headers.h"

#include "ArpParser.h"
#include "../network/network_headers.h"
#include "../include/nlohmann/json.hpp"
#include <sstream>

ArpParser::ArpParser() {}
ArpParser::~ArpParser() {}

std::string ArpParser::getName() const {
    return "arp";
}

// ARP 패킷은 이더넷 타입(0x0806)으로 식별되므로, 
// PacketParser의 메인 로직에서 직접 이 파서를 호출합니다.
// 따라서 isProtocol은 항상 false를 반환하여 다른 TCP/UDP 기반 파서와 혼동되지 않게 합니다.
bool ArpParser::isProtocol(const PacketInfo& info) const {
    return info.eth_type == 0x0806;
}

void ArpParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,dir,op,smac,sip,tmac,tip\n";
}

void ArpParser::parse(const PacketInfo& info) {
    if (info.payload_size < sizeof(ARPHeader)) return;

    const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(info.payload);

    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (void*)arp_header->spa, spa_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (void*)arp_header->tpa, tpa_str, INET_ADDRSTRLEN);

    uint16_t op_code = ntohs(arp_header->oper);
    std::string sha_str = mac_to_string(arp_header->sha);
    std::string tha_str = mac_to_string(arp_header->tha);

    std::string direction = (op_code == 1) ? "request" : (op_code == 2 ? "response" : "other");

    // JSONL 쓰기
    if (m_json_stream && m_json_stream->is_open()) {
        nlohmann::json details;
        details["op"] = op_code;
        details["smac"] = sha_str;
        details["sip"] = spa_str;
        details["tmac"] = tha_str;
        details["tip"] = tpa_str;
        writeJsonl(info, direction, details.dump());
    }

    // CSV 쓰기
    if (m_csv_stream && m_csv_stream->is_open()) {
        std::stringstream csv_line;
        csv_line << info.timestamp << ","
                 << direction << ","
                 << op_code << ","
                 << sha_str << ","
                 << spa_str << ","
                 << tha_str << ","
                 << tpa_str << "\n";
        *m_csv_stream << csv_line.str();
    }
}
