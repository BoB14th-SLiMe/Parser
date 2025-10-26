#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <string>
#include <utility> // For std::pair
#include <tuple>   // For std::tuple
#include "pcap.h"

class ArpParser {
public:
    ArpParser();
    ~ArpParser();
    
    // --- 수정: 반환 타입을 튜플로 변경 (JSON 문자열 대신 파싱된 필드) ---
    // timestamp_str, op_code, sha_str, spa_str, tha_str, tpa_str
    std::tuple<std::string, uint16_t, std::string, std::string, std::string, std::string> 
    parse(const struct pcap_pkthdr* header, const u_char* arp_payload, int size);

private:
    std::string mac_to_string(const uint8_t* mac);
};

#endif // ARP_PARSER_H
