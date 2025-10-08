#include "packet_parser/PacketParser.h"
#include "packet_parser/network_headers.h"
#include <iostream>
#include <netinet/in.h>

void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!packet) {
        std::cerr << "Invalid packet data." << std::endl;
        return;
    }

    // 1. Ethernet 헤더 파싱
    const EthernetHeader* eth_header = (const EthernetHeader*)packet;
    // IP 패킷(0x0800)이 아니면 무시
    if (ntohs(eth_header->eth_type) != 0x0800) {
        return;
    }

    // 2. IP 헤더 파싱
    const IPHeader* ip_header = (const IPHeader*)(packet + sizeof(EthernetHeader));
    const int ip_header_length = ip_header->ip_hl * 4;

    // TCP 프로토콜(6)이 아니면 무시
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }
    
    // 3. TCP 헤더 파싱
    const TCPHeader* tcp_header = (const TCPHeader*)((const u_char*)ip_header + ip_header_length);
    const int tcp_header_length = tcp_header->th_off * 4;

    // 4. 데이터(Payload) 분리
    const u_char* payload = (const u_char*)tcp_header + tcp_header_length;
    const int payload_size = ntohs(ip_header->ip_len) - (ip_header_length + tcp_header_length);

    // 5. 정보 출력
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

    std::cout << "----------------------------------------\n";
    std::cout << src_ip_str << ":" << ntohs(tcp_header->th_sport)
              << " -> "
              << dst_ip_str << ":" << ntohs(tcp_header->th_dport) << "\n";
    
    std::cout << "  TCP Header Length: " << tcp_header_length << " bytes\n";
    std::cout << "  Payload Size: " << payload_size << " bytes\n";

    if (payload_size > 0 && payload) {
        std::cout << "  Payload (first 16 bytes): ";
        for (int i = 0; i < std::min(payload_size, 16); ++i) {
            printf("%02x ", payload[i]);
        }
        std::cout << "\n";
    }
    std::cout << "----------------------------------------\n\n";
}