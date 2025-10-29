#include "ArpParser.h"
#include "../network/network_headers.h"
#include <sstream>
#include <arpa/inet.h>

std::string ArpParser::getName() const {
    return "arp";
}

void ArpParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,dir,op,smac,sip,tmac,tip\n";
}

bool ArpParser::isProtocol(const PacketInfo& info) const {
    // ARP는 eth_type == 0x0806
    return info.eth_type == 0x0806 && static_cast<size_t>(info.payload_size) >= sizeof(ARPHeader);
}

void ArpParser::parse(const PacketInfo& info) {
    if (static_cast<size_t>(info.payload_size) < sizeof(ARPHeader)) return;

    const ARPHeader* arp = (const ARPHeader*)(info.payload);
    uint16_t oper = ntohs(arp->oper);
    
    std::string direction = (oper == 1) ? "request" : (oper == 2 ? "response" : "unknown");
    
    // Sender/Target MAC/IP 추출
    std::string sender_mac = mac_to_string(arp->sha);
    std::string target_mac = mac_to_string(arp->tha);
    
    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp->tpa, target_ip, INET_ADDRSTRLEN);

    // JSONL 작성
    std::stringstream details_ss;
    details_ss << R"({"op":)" << oper << R"(,"smac":")" << sender_mac 
               << R"(","sip":")" << sender_ip << R"(","tmac":")" << target_mac 
               << R"(","tip":")" << target_ip << R"("})";
    
    writeJsonl(info, direction, details_ss.str());

    // CSV 작성
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << direction << ","
                      << oper << ","
                      << sender_mac << ","
                      << sender_ip << ","
                      << target_mac << ","
                      << target_ip << "\n";
    }
}