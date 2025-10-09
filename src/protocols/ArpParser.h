#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <string>
#include "pcap.h"

class ArpParser {
public:
    ArpParser();
    ~ArpParser();
    
    // ARP 페이로드를 받아 파싱 후 JSON 문자열을 반환합니다.
    std::string parse(const u_char* arp_payload, int size);

private:
    // MAC 주소를 문자열로 변환하는 헬퍼 함수
    std::string mac_to_string(const uint8_t* mac);
};

#endif // ARP_PARSER_H
