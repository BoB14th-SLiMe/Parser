#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <string>
#include <utility> // For std::pair
#include "pcap.h"

class ArpParser {
public:
    ArpParser();
    ~ArpParser();
    
    // --- 수정: 반환 타입을 std::pair로 변경하여 타임스탬프와 상세 JSON을 분리 ---
    std::pair<std::string, std::string> parse(const struct pcap_pkthdr* header, const u_char* arp_payload, int size);

private:
    std::string mac_to_string(const uint8_t* mac);
};

#endif // ARP_PARSER_H

