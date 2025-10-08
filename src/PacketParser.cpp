#include "packet_parser/PacketParser.h"
#include "packet_parser/network_headers.h"
#include <iostream>
#include <netinet/in.h>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <cstring>

// --- 생성자, 소멸자, 유틸리티 함수 (이전과 동일) ---
PacketParser::PacketParser(const std::string& output_dir) : m_output_dir(output_dir) {
    mkdir(m_output_dir.c_str(), 0755);
}
PacketParser::~PacketParser() {
    for (auto& pair : m_file_streams) {
        if (pair.second.is_open()) pair.second.close();
    }
    save_profiles();
}
std::ofstream& PacketParser::get_file_stream(const std::string& protocol) {
    if (m_file_streams.find(protocol) == m_file_streams.end()) {
        std::string filename = m_output_dir + protocol + "_packets.csv";
        m_file_streams[protocol].open(filename);
        if (m_file_streams[protocol].is_open()) {
            m_file_streams[protocol] << "src_ip,src_port,dst_ip,dst_port,datagram\n";
        }
    }
    return m_file_streams[protocol];
}
std::string PacketParser::format_payload_to_hex(const u_char* payload, int size) {
    if (!payload || size <= 0) return "";
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < size; ++i) ss << std::setw(2) << static_cast<int>(payload[i]);
    return ss.str();
}
void PacketParser::save_profiles() {
    std::ofstream profile_file(m_output_dir + "unknown_traffic_profiles.csv");
    if (!profile_file.is_open()) return;
    profile_file << "flow_identifier,packet_count,total_bytes\n";
    for (const auto& pair : m_profiles) {
        profile_file << "\"" << pair.first << "\","
                     << pair.second.packet_count << ","
                     << pair.second.total_bytes << "\n";
    }
    profile_file.close();
}

// --- OT 프로토콜 DPI 함수들 (이전과 동일) ---
bool PacketParser::is_modbus_signature(const u_char* payload, int size) { return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00; }
bool PacketParser::is_dnp3_signature(const u_char* payload, int size) { return size >= 2 && payload[0] == 0x05 && payload[1] == 0x64; }
bool PacketParser::is_s7_signature(const u_char* payload, int size) { if (size < 8 || payload[0] != 0x03) return false; uint8_t cotp_len = payload[4]; int s7_header_offset = 4 + 1 + cotp_len; if (size < s7_header_offset + 1) return false; return payload[s7_header_offset] == 0x32; }
bool PacketParser::is_ls_xgt_signature(const u_char* payload, int size) { if (size < 20) return false; return memcmp(payload, "LSIS-XGT", 8) == 0; }
bool PacketParser::is_mms_signature(const u_char* payload, int size) { if (size < 8 || payload[0] != 0x03) return false; uint8_t cotp_len = payload[4]; int mms_pdu_offset = 4 + 1 + cotp_len; if (size < mms_pdu_offset + 1) return false; return payload[mms_pdu_offset] != 0x32; }
bool PacketParser::is_ethernet_ip_signature(const u_char* payload, int size) { return size >= 24; }
bool PacketParser::is_iec104_signature(const u_char* payload, int size) { return size >= 2 && payload[0] == 0x68; }
bool PacketParser::is_opcua_signature(const u_char* payload, int size) { return size >= 3 && memcmp(payload, "OPC", 3) == 0; }
bool PacketParser::is_bacnet_signature(const u_char* payload, int size) { return size >= 4 && payload[0] == 0x81 && (payload[1] == 0x0a || payload[1] == 0x0b); }

// (핵심 추가) 네트워크 관리 프로토콜 DPI 함수들
bool PacketParser::is_dhcp_signature(const u_char* payload, int size) {
    // DHCP 메시지는 최소 240바이트이며, 236번 오프셋에 매직 쿠키(0x63825363)가 존재
    if (size < 240) return false;
    uint32_t magic_cookie = ntohl(*(uint32_t*)(payload + 236));
    return magic_cookie == 0x63825363;
}
bool PacketParser::is_dns_signature(const u_char* payload, int size) {
    // DNS 헤더는 12바이트
    return size >= 12;
}

// --- 메인 파싱 함수 ---
void PacketParser::parse(const u_char* packet, int packet_len) {
    if (!packet || packet_len < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth_header = (const EthernetHeader*)packet;
    uint16_t eth_type = ntohs(eth_header->eth_type);

    // 1단계: L2 (EtherType) 기반 프로토콜 식별
    if (eth_type == 0x0806) { // ARP
        get_file_stream("arp") << "N/A,N/A,N/A,N/A," << format_payload_to_hex(packet, packet_len) << "\n";
        return;
    }
    if (eth_type == 0x88B8) { get_file_stream("goose") << "N/A,N/A,N/A,N/A," << format_payload_to_hex(packet, packet_len) << "\n"; return; }
    if (eth_type == 0x8892) { get_file_stream("profinet_rt") << "N/A,N/A,N/A,N/A," << format_payload_to_hex(packet, packet_len) << "\n"; return; }
    if (eth_type != 0x0800) return; // IPv4가 아니면 종료

    // 2단계: L3/L4 기반 프로토콜 식별
    if (packet_len < sizeof(EthernetHeader) + sizeof(IPHeader)) return;
    const IPHeader* ip_header = (const IPHeader*)(packet + sizeof(EthernetHeader));
    const int ip_header_length = ip_header->hl * 4;
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
    
    std::string identified_protocol = "";
    const u_char* payload = nullptr;
    int payload_size = 0;
    uint16_t src_port = 0, dst_port = 0;

    // --- TCP 프로토콜 처리 ---
    if (ip_header->p == IPPROTO_TCP) {
        if (packet_len < sizeof(EthernetHeader) + ip_header_length + sizeof(TCPHeader)) return;
        const TCPHeader* tcp_header = (const TCPHeader*)((const u_char*)ip_header + ip_header_length);
        const int tcp_header_length = tcp_header->off * 4;
        payload = (const u_char*)tcp_header + tcp_header_length;
        payload_size = ntohs(ip_header->len) - (ip_header_length + tcp_header_length);
        src_port = ntohs(tcp_header->sport);
        dst_port = ntohs(tcp_header->dport);

        if (payload_size > 0) {
            // 3단계: L7 (DPI) 기반 프로토콜 식별
            if (is_modbus_signature(payload, payload_size)) identified_protocol = "modbus_tcp";
            else if (is_s7_signature(payload, payload_size)) identified_protocol = "s7comm";
            else if (is_mms_signature(payload, payload_size) && (dst_port == 102 || src_port == 102)) identified_protocol = "mms";
            else if (is_ls_xgt_signature(payload, payload_size)) identified_protocol = "ls_xgt";
            else if (is_dnp3_signature(payload, payload_size)) identified_protocol = "dnp3";
            else if (is_ethernet_ip_signature(payload, payload_size) && (dst_port == 44818 || src_port == 44818)) identified_protocol = "ethernet_ip_control";
            else if (is_iec104_signature(payload, payload_size)) identified_protocol = "iec104";
            else if (is_opcua_signature(payload, payload_size)) identified_protocol = "opcua";
        } else {
            identified_protocol = "tcp_session";
        }
    }
    // --- UDP 프로토콜 처리 ---
    else if (ip_header->p == IPPROTO_UDP) {
        if (packet_len < sizeof(EthernetHeader) + ip_header_length + sizeof(UDPHeader)) return;
        const UDPHeader* udp_header = (const UDPHeader*)((const u_char*)ip_header + ip_header_length);
        payload = (const u_char*)udp_header + sizeof(UDPHeader);
        payload_size = ntohs(udp_header->len) - sizeof(UDPHeader);
        src_port = ntohs(udp_header->sport);
        dst_port = ntohs(udp_header->dport);
        
        if (payload_size > 0) {
            // (핵심 추가) DHCP, DNS 등 UDP 기반 프로토콜 식별
            if ((dst_port == 67 || src_port == 67 || dst_port == 68 || src_port == 68) && is_dhcp_signature(payload, payload_size)) {
                identified_protocol = "dhcp";
            } else if ((dst_port == 53 || src_port == 53) && is_dns_signature(payload, payload_size)) {
                identified_protocol = "dns";
            } else if ((dst_port == 2222 || src_port == 2222)) {
                identified_protocol = "ethernet_ip_io";
            } else if (is_bacnet_signature(payload, payload_size)) {
                identified_protocol = "bacnet_ip";
            }
        }
    }

    // --- 식별된 프로토콜 파일에 저장 또는 프로파일링 ---
    if (!identified_protocol.empty()) {
        get_file_stream(identified_protocol) << src_ip_str << "," << src_port << "," << dst_ip_str << "," << dst_port << "," << format_payload_to_hex(payload, payload_size) << "\n";
    } else if (payload_size > 0) { // 알려진 프로토콜이 아니면서 데이터가 있는 경우만 프로파일링
        std::string proto_str = (ip_header->p == IPPROTO_TCP) ? " (TCP)" : " (UDP)";
        std::string flow_id = std::string(src_ip_str) + ":" + std::to_string(src_port) + " -> " + std::string(dst_ip_str) + ":" + std::to_string(dst_port) + proto_str;
        m_profiles[flow_id].packet_count++;
        m_profiles[flow_id].total_bytes += payload_size;
    }
}

