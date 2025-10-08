#include <iostream>
#include <pcap.h>
#include "packet_parser/PacketParser.h"
#include "packet_parser/network_headers.h"

// 콜백 함수: PacketParser의 parse 멤버 함수를 직접 호출
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketParser* parser = reinterpret_cast<PacketParser*>(user_data);
    // Ethernet 헤더 타입 체크 (IP 패킷인지 확인)
    const EthernetHeader* eth_header = (const EthernetHeader*)packet;
    if (ntohs(eth_header->eth_type) == 0x0800) { // 0x0800 -> IPv4
         parser->parse(packet);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open pcap file " << argv[1] << ": " << errbuf << std::endl;
        return 2;
    }

    // PacketParser 객체 생성 (기본 output/ 디렉토리 사용)
    PacketParser parser;

    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&parser)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
    }

    std::cout << "Application-layer packet parsing complete." << std::endl;
    pcap_close(handle);
    return 0;
}

