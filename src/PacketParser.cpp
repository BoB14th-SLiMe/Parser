#include "PacketParser.h"
#include "network_headers.h"
#include <iostream>
#include <netinet/in.h>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <cstring>
#include <algorithm>
#include <vector>

// --- 생성자, 소멸자 ---
PacketParser::PacketParser(const std::string& output_dir)
    : m_output_dir(output_dir), m_timeout(5000) { // timeout 러프하게 5초
    mkdir(m_output_dir.c_str(), 0755);
}

PacketParser::~PacketParser() {
    for (auto& pair : m_file_streams) {
        if (pair.second.is_open()) pair.second.close();
    }
    // (수정) 프로토콜별 매핑 파일 스트림 모두 닫기
    for (auto& pair : m_mapped_protocol_streams) {
        if (pair.second.is_open()) pair.second.close();
    }
    save_profiles();
}

// (추가) 프로토콜별 매핑 파일 스트림을 가져오는 함수 구현
std::ofstream& PacketParser::get_mapped_stream(const std::string& protocol) {
    if (m_mapped_protocol_streams.find(protocol) == m_mapped_protocol_streams.end()) {
        std::string filename = m_output_dir + protocol + "_mapped.csv";
        m_mapped_protocol_streams[protocol].open(filename);
        if (m_mapped_protocol_streams[protocol].is_open()) {
            m_mapped_protocol_streams[protocol] << "req_ip,req_port,res_ip,res_port,req_payload,res_payload\n";
        }
    }
    return m_mapped_protocol_streams[protocol];
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

std::string PacketParser::get_canonical_flow_id(const std::string& ip1_str, uint16_t port1, const std::string& ip2_str, uint16_t port2) {
    std::string ip1 = ip1_str, ip2 = ip2_str;
    if (ip1 > ip2 || (ip1 == ip2 && port1 > port2)) {
        std::swap(ip1, ip2);
        std::swap(port1, port2);
    }
    return ip1 + ":" + std::to_string(port1) + "-" + ip2 + ":" + std::to_string(port2);
}

// --- OT 프로토콜 DPI 함수들 ---
bool PacketParser::is_modbus_signature(const u_char* payload, int size) { return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00; }
bool PacketParser::is_dnp3_signature(const u_char* payload, int size) { return size >= 2 && payload[0] == 0x05 && payload[1] == 0x64; }
bool PacketParser::is_s7_signature(const u_char* payload, int size) { if (size < 8 || payload[0] != 0x03) return false; uint8_t cotp_len = payload[4]; int s7_header_offset = 4 + 1 + cotp_len; if (size < s7_header_offset + 1) return false; return payload[s7_header_offset] == 0x32; }
bool PacketParser::is_ls_xgt_signature(const u_char* payload, int size) { if (size < 20) return false; return memcmp(payload, "LSIS-XGT", 8) == 0; }
bool PacketParser::is_mms_signature(const u_char* payload, int size) { if (size < 8 || payload[0] != 0x03) return false; uint8_t cotp_len = payload[4]; int mms_pdu_offset = 4 + 1 + cotp_len; if (size < mms_pdu_offset + 1) return false; return payload[mms_pdu_offset] != 0x32; }
bool PacketParser::is_ethernet_ip_signature(const u_char* payload, int size) { return size >= 24; }
bool PacketParser::is_iec104_signature(const u_char* payload, int size) { return size >= 2 && payload[0] == 0x68; }
bool PacketParser::is_opcua_signature(const u_char* payload, int size) { return size >= 3 && memcmp(payload, "OPC", 3) == 0; }
bool PacketParser::is_bacnet_signature(const u_char* payload, int size) { return size >= 4 && payload[0] == 0x81 && (payload[1] == 0x0a || payload[1] == 0x0b); }
bool PacketParser::is_dhcp_signature(const u_char* payload, int size) { if (size < 240) return false; uint32_t magic_cookie = ntohl(*(uint32_t*)(payload + 236)); return magic_cookie == 0x63825363; }
bool PacketParser::is_dns_signature(const u_char* payload, int size) { return size >= 12; }


// --- 메인 파싱 함수 ---
void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    auto current_time = std::chrono::steady_clock::now();

    // 타임아웃된 요청 정리 (Garbage Collection)
    for (auto& flow_pair : m_pending_requests) {
        std::vector<uint32_t> timed_out_acks;
        for (const auto& req_pair : flow_pair.second) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - req_pair.second.timestamp);
            if (elapsed > m_timeout) {
                timed_out_acks.push_back(req_pair.first);
            }
        }
        for (uint32_t ack : timed_out_acks) {
            flow_pair.second.erase(ack);
        }
    }

    if (!packet || header->caplen < sizeof(EthernetHeader)) return;
    int packet_len = header->caplen;

    const EthernetHeader* eth_header = (const EthernetHeader*)packet;
    if (ntohs(eth_header->eth_type) != 0x0800) return; // IPv4가 아니면 종료

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

        // ===============================================
        //  Part 1: 프로토콜별 요청/응답 쌍 매핑 로직
        // ===============================================
        uint32_t seq_num = ntohl(tcp_header->seq);
        uint32_t ack_num = ntohl(tcp_header->ack);
        std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
        bool is_reply = false;

        if (m_pending_requests.count(flow_id) && m_pending_requests[flow_id].count(ack_num)) {
            is_reply = true;
            RequestInfo req_info = m_pending_requests[flow_id][ack_num];
            std::ofstream& out_stream = get_mapped_stream(req_info.protocol);
            if (out_stream.is_open()) {
                 out_stream << dst_ip_str << "," << dst_port << ","
                            << src_ip_str << "," << src_port << ","
                            << req_info.request_payload << ","
                            << format_payload_to_hex(payload, payload_size) << "\n";
            }
            m_pending_requests[flow_id].erase(ack_num);
        }


        // 2. 이 패킷이 새로운 "요청"일 경우
        if (payload_size > 0 && !is_reply) {
            uint32_t next_seq = seq_num + payload_size;
            RequestInfo new_req;
            new_req.request_payload = format_payload_to_hex(payload, payload_size);
            new_req.timestamp = current_time;
            m_pending_requests[flow_id][next_seq] = new_req;
        }

        if (payload_size > 0 && !is_reply) {
            std::string req_protocol = "";
            if (is_modbus_signature(payload, payload_size)) req_protocol = "modbus_tcp";
            else if (is_s7_signature(payload, payload_size)) req_protocol = "s7comm";
            else if (is_mms_signature(payload, payload_size) && (dst_port == 102 || src_port == 102)) identified_protocol = "mms";
            else if (is_ls_xgt_signature(payload, payload_size)) identified_protocol = "ls_xgt";
            else if (is_dnp3_signature(payload, payload_size)) identified_protocol = "dnp3";
            else if (is_ethernet_ip_signature(payload, payload_size) && (dst_port == 44818 || src_port == 44818)) identified_protocol = "ethernet_ip_control";
            else if (is_iec104_signature(payload, payload_size)) identified_protocol = "iec104";
            else if (is_opcua_signature(payload, payload_size)) identified_protocol = "opcua";

            // (핵심 수정) 프로토콜이 식별된 경우에만 요청으로 저장
            if (!req_protocol.empty()) {
                RequestInfo new_req;
                new_req.request_payload = format_payload_to_hex(payload, payload_size);
                new_req.timestamp = current_time;
                new_req.protocol = req_protocol;
                m_pending_requests[flow_id][seq_num + payload_size] = new_req;
            }
        }

        // =======================================================
        //  Part 2: 모든 TCP 패킷에 대한 개별 분류 및 저장 로직 (복원)
        // =======================================================
        std::string individual_protocol = "";
        if (payload_size > 0) {
            if (is_modbus_signature(payload, payload_size)) individual_protocol = "modbus_tcp";
            else if (is_s7_signature(payload, payload_size)) individual_protocol = "s7comm";
            else if (is_dnp3_signature(payload, payload_size)) individual_protocol = "dnp3";
            else if (is_mms_signature(payload, payload_size) && (dst_port == 102 || src_port == 102)) individual_protocol = "mms";
            else if (is_ls_xgt_signature(payload, payload_size)) individual_protocol = "ls_xgt";
            else if (is_ethernet_ip_signature(payload, payload_size) && (dst_port == 44818 || src_port == 44818)) individual_protocol = "ethernet_ip_control";
            else if (is_iec104_signature(payload, payload_size)) individual_protocol = "iec104";
            else if (is_opcua_signature(payload, payload_size)) individual_protocol = "opcua";
        } else {
            // 페이로드가 없으면 순수 TCP 세션 제어 패킷으로 분류
            individual_protocol = "tcp_session";
        }

        if (!individual_protocol.empty()) {
            get_file_stream(individual_protocol) << src_ip_str << "," << src_port << "," << dst_ip_str << "," << dst_port << "," << format_payload_to_hex(payload, payload_size) << "\n";
        } else if (payload_size > 0) {
            // 페이로드는 있지만 알려진 프로토콜이 아닌 경우, 'unknown'으로 프로파일링
            std::string proto_str = " (TCP)";
            std::string flow_id_str = std::string(src_ip_str) + ":" + std::to_string(src_port) + " -> " + std::string(dst_ip_str) + ":" + std::to_string(dst_port) + proto_str;
            m_profiles[flow_id_str].packet_count++;
            m_profiles[flow_id_str].total_bytes += payload_size;
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
    } else if (payload_size > 0) {
        std::string proto_str = (ip_header->p == IPPROTO_TCP) ? " (TCP)" : " (UDP)";
        std::string flow_id_str = std::string(src_ip_str) + ":" + std::to_string(src_port) + " -> " + std::string(dst_ip_str) + ":" + std::to_string(dst_port) + proto_str;
        m_profiles[flow_id_str].packet_count++;
        m_profiles[flow_id_str].total_bytes += payload_size;
    }
}

