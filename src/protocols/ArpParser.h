#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <string>
#include <utility> // For std::pair
#include <tuple>   // --- tuple 헤더 추가 ---
#include "pcap.h"

class ArpParser {
public:
    ArpParser();
    ~ArpParser();
    
    // --- 수정: 반환 타입을 std::tuple로 변경 (timestamp, json_details, op_code) ---
    std::tuple<std::string, std::string, int> parse(const struct pcap_pkthdr* header, const u_char* arp_payload, int size);

private:
    std::string mac_to_string(const uint8_t* mac);
};

#endif // ARP_PARSER_H
