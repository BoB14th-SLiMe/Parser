#include "packet_parser/PacketParser.h"
#include "packet_parser/network_headers.h"
#include <iostream>
#include <netinet/in.h>
#include <iomanip>
#include <sstream>

// 생성자
PacketParser::PacketParser(const std::string& tcp_filename, const std::string& udp_filename) {
    m_tcp_csv_file.open(tcp_filename);
    if (m_tcp_csv_file.is_open()) {
        m_tcp_csv_file << "src_ip,src_port,dst_ip,dst_port,datagram\n";
    } else {
        std::cerr << "Error: Could not open TCP output file: " << tcp_filename << std::endl;
    }
    // UDP 파일 로직은 필요 시 여기에 추가
}

// 소멸자
PacketParser::~PacketParser() {
    if (m_tcp_csv_file.is_open()) {
        m_tcp_csv_file.close();
    }
    if (m_udp_csv_file.is_open()) {
        m_udp_csv_file.close();
    }
}

// 16진수 문자열로 변환하는 헬퍼 함수
std::string PacketParser::format_payload_to_hex(const u_char* payload, int size) {
    if (!payload || size <= 0) {
        return "";
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<int>(payload[i]);
    }
    return ss.str();
}

void PacketParser::parse(const u_char* packet) {
    if (!packet) return;

    const IPHeader* ip_header = (const IPHeader*)(packet + sizeof(EthernetHeader));
    const int ip_header_length = ip_header->ip_hl * 4;

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
    
    if (ip_header->ip_p == IPPROTO_TCP) {
        const TCPHeader* tcp_header = (const TCPHeader*)((const u_char*)ip_header + ip_header_length);
        const int tcp_header_length = tcp_header->th_off * 4;
        const int payload_size = ntohs(ip_header->ip_len) - (ip_header_length + tcp_header_length);
        const u_char* payload = (const u_char*)tcp_header + tcp_header_length;

        if (m_tcp_csv_file.is_open()) {
            m_tcp_csv_file << src_ip_str << ","
                           << ntohs(tcp_header->th_sport) << ","
                           << dst_ip_str << ","
                           << ntohs(tcp_header->th_dport) << ","
                           << format_payload_to_hex(payload, payload_size) << "\n";
        }
    }
    // UDP 로직은 여기에 추가
}

