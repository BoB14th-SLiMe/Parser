#include "PacketParser.h"
#include "network_headers.h"
#include <iostream>
#include <netinet/in.h>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <algorithm>
#include <ctime>
#include <memory> // std::unique_ptr를 위해 명시적으로 포함

// 구체적인 파서 구현 포함
#include "ModbusParser.h"
#include "S7CommParser.h"

PacketParser::PacketParser(const std::string& output_dir)
    : m_output_dir(output_dir) {
    mkdir(m_output_dir.c_str(), 0755);

    // --- 여기에 모든 프로토콜 파서를 등록합니다 ---
    // C++11 호환성을 위해 std::make_unique 대신 new 사용
    m_protocol_parsers.push_back(std::unique_ptr<S7CommParser>(new S7CommParser()));
    m_protocol_parsers.push_back(std::unique_ptr<ModbusParser>(new ModbusParser()));
    
    // --- 각 파서의 출력 파일을 초기화합니다 ---
    for (const auto& parser : m_protocol_parsers) {
        initialize_output_stream(parser->getName());
        parser->setOutputStream(&m_output_streams[parser->getName()]);
    }
}

PacketParser::~PacketParser() {
    for (auto& pair : m_output_streams) {
        if (pair.second.is_open()) pair.second.close();
    }
}

void PacketParser::initialize_output_stream(const std::string& protocol) {
    if (m_output_streams.find(protocol) == m_output_streams.end()) {
        std::string filename = m_output_dir + protocol + "_mapped.jsonl";
        m_output_streams[protocol].open(filename);
        if (!m_output_streams[protocol].is_open()) {
            std::cerr << "Error: Could not open output file " << filename << std::endl;
        }
    }
}

std::string PacketParser::get_canonical_flow_id(const std::string& ip1_str, uint16_t port1, const std::string& ip2_str, uint16_t port2) {
    std::string ip1 = ip1_str, ip2 = ip2_str;
    if (ip1 > ip2 || (ip1 == ip2 && port1 > port2)) {
        std::swap(ip1, ip2);
        std::swap(port1, port2);
    }
    return ip1 + ":" + std::to_string(port1) + "-" + ip2 + ":" + std::to_string(port2);
}

void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    // --- L2/L3/L4 파싱은 동일하게 유지 ---
    if (!packet || header->caplen < sizeof(EthernetHeader)) return;

    // Timestamp 생성
    struct tm *ltime;
    char timestr[40];
    time_t local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ltime);
    std::stringstream timestamp_ss;
    timestamp_ss << timestr << "." << std::setw(6) << std::setfill('0') << header->ts.tv_usec;
    std::string timestamp = timestamp_ss.str();

    const EthernetHeader* eth_header = (const EthernetHeader*)packet;
    if (ntohs(eth_header->eth_type) != 0x0800) return;

    if (header->caplen < sizeof(EthernetHeader) + sizeof(IPHeader)) return;
    const IPHeader* ip_header = (const IPHeader*)(packet + sizeof(EthernetHeader));
    
    const int ip_header_length = ip_header->hl * 4;
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
    
    if (ip_header->p == IPPROTO_TCP) {
        if (header->caplen < (sizeof(EthernetHeader) + ip_header_length + sizeof(TCPHeader))) return;
        
        const TCPHeader* tcp_header = (const TCPHeader*)((const u_char*)ip_header + ip_header_length);
        const int tcp_header_length = tcp_header->off * 4;
        const u_char* payload = (const u_char*)tcp_header + tcp_header_length;
        int payload_size = ntohs(ip_header->len) - (ip_header_length + tcp_header_length);
        
        uint16_t src_port = ntohs(tcp_header->sport);
        uint16_t dst_port = ntohs(tcp_header->dport);
        std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
        
        // --- 위임 로직 ---
        // 등록된 파서들을 순회하며 작업을 위임합니다.
        for (const auto& parser : m_protocol_parsers) {
            if (parser->isProtocol(payload, payload_size)) {
                
                // 정보 구조체 구성
                PacketInfo info = {
                    timestamp,
                    flow_id,
                    src_ip_str,
                    src_port,
                    dst_ip_str,
                    dst_port,
                    payload,
                    payload_size
                };

                parser->parse(info);
                break; // 핸들러를 찾았으므로 검색 중단
            }
        }
    }
}

