#include "packet_parser/PacketParser.h"
#include "packet_parser/network_headers.h"
#include <iostream>
#include <netinet/in.h>
#include <iomanip>
#include <sstream>
#include <sys/stat.h> // mkdir

// 생성자
PacketParser::PacketParser(const std::string& output_dir) : m_output_dir(output_dir) {
    // output 디렉토리가 없으면 생성
    mkdir(m_output_dir.c_str(), 0755);
}

// 소멸자
PacketParser::~PacketParser() {
    // 맵에 있는 모든 파일 스트림을 순회하며 닫는다.
    for (auto it = m_file_streams.begin(); it != m_file_streams.end(); ++it) {
        if (it->second.is_open()) {
            it->second.close();
        }
    }
}

// 프로토콜 이름으로 파일 스트림을 가져오거나 생성하는 함수
std::ofstream& PacketParser::get_file_stream(const std::string& protocol) {
    // 맵에서 해당 프로토콜의 파일 스트림을 찾는다.
    auto it = m_file_streams.find(protocol);
    if (it == m_file_streams.end()) {
        // 찾지 못했다면 새로 생성
        std::string filename = m_output_dir + protocol + "_packets.csv";
        m_file_streams[protocol].open(filename);
        if (m_file_streams[protocol].is_open()) {
            // 새로 생성된 파일이라면 CSV 헤더를 작성한다.
            m_file_streams[protocol] << "src_ip,src_port,dst_ip,dst_port,datagram\n";
        } else {
            std::cerr << "Error: Could not open output file: " << filename << std::endl;
        }
        return m_file_streams[protocol];
    }
    // 이미 있다면 기존 스트림을 반환
    return it->second;
}


// 16진수 문자열로 변환하는 헬퍼 함수
std::string PacketParser::format_payload_to_hex(const u_char* payload, int size) {
    if (!payload || size <= 0) return "";
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
        const u_char* payload = (const u_char*)tcp_header + tcp_header_length;
        const int payload_size = ntohs(ip_header->ip_len) - (ip_header_length + tcp_header_length);
        
        uint16_t dst_port = ntohs(tcp_header->th_dport);
        std::string protocol_name;

        // 목적지 포트 번호로 애플리케이션 프로토콜 식별
        switch(dst_port) {
            case 502:
                protocol_name = "modbus_tcp";
                break;
            case 1883:
            case 8883:
                protocol_name = "mqtt";
                break;
            case 80:
                protocol_name = "http";
                break;
            case 443:
                protocol_name = "https_tls";
                break;
            default:
                protocol_name = "generic_tcp";
                break;
        }

        std::ofstream& out_file = get_file_stream(protocol_name);
        if(out_file.is_open()) {
            out_file << src_ip_str << ","
                     << ntohs(tcp_header->th_sport) << ","
                     << dst_ip_str << ","
                     << dst_port << ","
                     << format_payload_to_hex(payload, payload_size) << "\n";
        }

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        // UDP 로직도 필요하다면 여기에 유사하게 구현 가능
        // 예: DNS (port 53), DHCP (port 67, 68) 등
        std::ofstream& out_file = get_file_stream("generic_udp");
        // ... UDP 데이터 저장 로직 ...
    }
}

