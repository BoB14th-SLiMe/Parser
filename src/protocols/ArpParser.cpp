#include "ArpParser.h"
#include "../network/network_headers.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>
#include <cstring>

ArpParser::ArpParser() {}
ArpParser::~ArpParser() {}

std::string ArpParser::mac_to_string(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac[i]) << (i < 5 ? ":" : "");
    }
    return ss.str();
}

// --- MODIFICATION: Ensure implementation matches 2-argument signature ---
std::string ArpParser::parse(const u_char* arp_payload, int size) {
    if (size < sizeof(ARPHeader)) {
        return "{\"err\":\"invalid_size\"}";
    }

    const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(arp_payload);
    std::stringstream ss;

    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->spa, spa_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->tpa, tpa_str, INET_ADDRSTRLEN);

    ss << "{\"op\":" << ntohs(arp_header->oper)
       << ",\"smac\":\"" << mac_to_string(arp_header->sha) << "\""
       << ",\"sip\":\"" << spa_str << "\""
       << ",\"tmac\":\"" << mac_to_string(arp_header->tha) << "\""
       << ",\"tip\":\"" << tpa_str << "\"}";

    return ss.str();
}

