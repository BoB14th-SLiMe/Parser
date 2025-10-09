#include "PacketParser.h"
#include "./network/network_headers.h"
#include <iostream>
#include <netinet/in.h>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <algorithm>
#include <ctime>
#include <memory>
#include <cstring>

// 모든 프로토콜 파서 헤더 포함
#include "./protocols/ModbusParser.h"
#include "./protocols/S7CommParser.h"
#include "./protocols/XgtFenParser.h"
#include "./protocols/Dnp3Parser.h"
#include "./protocols/DnsParser.h"
#include "./protocols/GenericParser.h"
#include "./protocols/UnknownParser.h"
#include "./protocols/ArpParser.h"
#include "./protocols/TcpSessionParser.h"

PacketParser::PacketParser(const std::string& output_dir)
    : m_output_dir(output_dir) {
    mkdir(m_output_dir.c_str(), 0755);

    // 독립 파서들을 초기화합니다.
    m_arp_parser = std::unique_ptr<ArpParser>(new ArpParser());
    m_tcp_session_parser = std::unique_ptr<TcpSessionParser>(new TcpSessionParser());
    initialize_output_stream("arp");
    initialize_output_stream("tcp_session");
    
    // IP 페이로드 기반 프로토콜 파서들을 벡터에 등록합니다.
    m_protocol_parsers.push_back(std::unique_ptr<ModbusParser>(new ModbusParser()));
    m_protocol_parsers.push_back(std::unique_ptr<S7CommParser>(new S7CommParser()));
    m_protocol_parsers.push_back(std::unique_ptr<XgtFenParser>(new XgtFenParser()));
    m_protocol_parsers.push_back(std::unique_ptr<Dnp3Parser>(new Dnp3Parser()));
    m_protocol_parsers.push_back(std::unique_ptr<DnsParser>(new DnsParser()));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("ethernet_ip")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("iec104")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("mms")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("opc_ua")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("bacnet")));
    m_protocol_parsers.push_back(std::unique_ptr<GenericParser>(new GenericParser("dhcp")));
    m_protocol_parsers.push_back(std::unique_ptr<UnknownParser>(new UnknownParser())); // 항상 마지막에 위치

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
        std::string filename = m_output_dir + protocol + ".jsonl";
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
    if (!packet || header->caplen < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth_header = (const EthernetHeader*)(packet);
    uint16_t eth_type = ntohs(eth_header->eth_type);
    const u_char* l3_payload = packet + sizeof(EthernetHeader);
    int l3_payload_size = header->caplen - sizeof(EthernetHeader);

    if (eth_type == 0x0806) { // ARP (Layer 2)
        std::string details_json = m_arp_parser->parse(l3_payload, l3_payload_size);
        
        struct tm *ltime;
        char timestr[40];
        ltime = localtime(&header->ts.tv_sec);
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ltime);
        
        std::ofstream& out_stream = m_output_streams["arp"];
        if (out_stream.is_open()) {
            out_stream << "{\"ts\":\"" << timestr << "." << std::setw(6) << std::setfill('0') << header->ts.tv_usec << "\","
                       << "\"d\":" << details_json << "}\n";
        }
    }
    else if (eth_type == 0x0800) { // IPv4 (Layer 3)
        if (l3_payload_size < sizeof(IPHeader)) return;
        const IPHeader* ip_header = (const IPHeader*)(l3_payload);
        
        const int ip_header_length = ip_header->hl * 4;
        char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

        if (ip_header->p == IPPROTO_TCP || ip_header->p == IPPROTO_UDP) {
            const u_char* payload;
            int payload_size;
            uint16_t src_port = 0, dst_port = 0;
            uint32_t tcp_seq = 0, tcp_ack = 0;
            uint8_t tcp_flags = 0;

            if (ip_header->p == IPPROTO_TCP) {
                 if (l3_payload_size < ip_header_length + sizeof(TCPHeader)) return;
                 const TCPHeader* tcp_header = (const TCPHeader*)(l3_payload + ip_header_length);
                 const int tcp_header_length = tcp_header->off * 4;
                 payload = (const u_char*)tcp_header + tcp_header_length;
                 payload_size = ntohs(ip_header->len) - (ip_header_length + tcp_header_length);
                 src_port = ntohs(tcp_header->sport);
                 dst_port = ntohs(tcp_header->dport);
                 tcp_seq = ntohl(tcp_header->seq);
                 tcp_ack = ntohl(tcp_header->ack);
                 tcp_flags = tcp_header->flags;
            } else { // UDP
                struct UDPHeader { uint16_t sport, dport, len, check; };
                if (l3_payload_size < ip_header_length + sizeof(UDPHeader)) return;
                const UDPHeader* udp_header = (const UDPHeader*)(l3_payload + ip_header_length);
                payload = (const u_char*)udp_header + sizeof(UDPHeader);
                payload_size = ntohs(udp_header->len) - sizeof(UDPHeader);
                src_port = ntohs(udp_header->sport);
                dst_port = ntohs(udp_header->dport);
            }

            std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
            std::stringstream time_ss;
            if (m_flow_start_times.find(flow_id) == m_flow_start_times.end()) {
                m_flow_start_times[flow_id] = header->ts;
                struct tm *ltime;
                char timestr[40];
                ltime = localtime(&header->ts.tv_sec);
                strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ltime);
                time_ss << "{\"ts\":\"" << timestr << "." << std::setw(6) << std::setfill('0') << header->ts.tv_usec << "\",";
            } else {
                long long delta_us = (header->ts.tv_sec - m_flow_start_times[flow_id].tv_sec) * 1000000LL + (header->ts.tv_usec - m_flow_start_times[flow_id].tv_usec);
                time_ss << "{\"td\":" << delta_us << ",";
            }
            
            // --- 페이로드 크기에 따른 로직 분기 ---
            if (payload_size <= 0 && ip_header->p == IPPROTO_TCP) {
                // 페이로드가 없는 TCP 세션 유지 패킷 처리
                std::ofstream& out_stream = m_output_streams["tcp_session"];
                if (out_stream.is_open()) {
                    std::string details_json = m_tcp_session_parser->parse(tcp_seq, tcp_ack, tcp_flags);
                    out_stream << time_ss.str() 
                               << "\"sip\":\"" << src_ip_str << "\",\"sp\":" << src_port << ","
                               << "\"dip\":\"" << dst_ip_str << "\",\"dp\":" << dst_port << ","
                               << "\"d\":" << details_json << "}\n";
                }
                return; // 처리 완료 후 함수 종료
            }

            bool matched = false;
            for (const auto& parser : m_protocol_parsers) {
                if (parser->getName() != "unknown" && parser->isProtocol(payload, payload_size)) {
                    PacketInfo info = {
                        time_ss.str(), flow_id, src_ip_str, src_port, dst_ip_str, dst_port,
                        payload, payload_size, tcp_seq, tcp_ack, tcp_flags
                    };
                    parser->parse(info);
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                 m_protocol_parsers.back()->parse({time_ss.str(), flow_id, src_ip_str, src_port, dst_ip_str, dst_port,
                        payload, payload_size, tcp_seq, tcp_ack, tcp_flags});
            }
        }
    }
}

