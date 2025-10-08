#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h> // pcap_pkthdr 구조체를 사용하기 위함

class PacketParser {
public:
    // 패킷을 받아 파싱을 수행하는 메인 함수
    void parse(const struct pcap_pkthdr* header, const u_char* packet);
};

#endif // PACKET_PARSER_H