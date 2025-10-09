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
#include <ctime>

PacketParser::PacketParser(const std::string& output_dir)
    : m_output_dir(output_dir), m_timeout(5000) {
    mkdir(m_output_dir.c_str(), 0755);
}

PacketParser::~PacketParser() {
    for (auto& pair : m_mapped_protocol_streams) {
        if (pair.second.is_open()) pair.second.close();
    }
    save_profiles();
}

std::ofstream& PacketParser::get_mapped_stream(const std::string& protocol) {
    if (m_mapped_protocol_streams.find(protocol) == m_mapped_protocol_streams.end()) {
        std::string filename = m_output_dir + protocol + "_mapped.csv";
        m_mapped_protocol_streams[protocol].open(filename);
        if (m_mapped_protocol_streams[protocol].is_open()) {
            if (protocol == "modbus_tcp") {
                // (수정) "timestamp" 열 추가
                m_mapped_protocol_streams[protocol] << "timestamp,src_ip,src_port,dst_ip,dst_port,type,trans_id,proto_id,length,unit_id,func_code,details\n";
            } else {
                m_mapped_protocol_streams[protocol] << "req_ip,req_port,res_ip,res_port,req_payload,res_payload\n";
            }
        }
    }
    return m_mapped_protocol_streams[protocol];
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
        profile_file << "\"" << pair.first << "\"," << pair.second.packet_count << "," << pair.second.total_bytes << "\n";
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

bool PacketParser::is_modbus_signature(const u_char* payload, int size) { return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00; }
bool PacketParser::is_s7_signature(const u_char* payload, int size) { return false; /* Placeholder */ }

std::string get_modbus_function_name(uint8_t fc) {
    switch (fc) {
        case 1: return "Read Coils";
        case 2: return "Read Discrete Inputs";
        case 3: return "Read Holding Registers";
        case 4: return "Read Input Registers";
        case 5: return "Write Single Coil";
        case 6: return "Write Single Register";
        case 15: return "Write Multiple Coils";
        case 16: return "Write Multiple Registers";
        default: return "Unknown Function";
    }
}

ModbusInfo PacketParser::parse_modbus_payload(const u_char* payload, int payload_size, bool is_request) {
    ModbusInfo info;
    if (payload_size < 8) return info;

    info.transaction_id = ntohs(*(uint16_t*)(payload));
    info.protocol_id = ntohs(*(uint16_t*)(payload + 2));
    info.length = ntohs(*(uint16_t*)(payload + 4));
    info.unit_id = payload[6];
    uint8_t function_code = payload[7];
    
    std::stringstream ss;
    ss << get_modbus_function_name(function_code & 0x7F) << ", ";

    const u_char* pdu_data = payload + 8;
    
    uint16_t start_addr = 0, quantity = 0, addr = 0, val = 0;
    uint8_t byte_count = 0;

    if (function_code > 0x80) { // Exception
        uint8_t exception_code = pdu_data[0];
        ss << "Exception: " << (int)exception_code;
    } else {
        switch (function_code) {
            case 1: case 2: case 3: case 4:
                if (is_request) {
                    start_addr = ntohs(*(uint16_t*)(pdu_data));
                    quantity = ntohs(*(uint16_t*)(pdu_data + 2));
                    ss << "Start: " << start_addr << ", Quantity: " << quantity;
                } else {
                    byte_count = pdu_data[0];
                    ss << (int)byte_count << " bytes data";
                }
                break;
            case 5: case 6:
                addr = ntohs(*(uint16_t*)(pdu_data));
                val = ntohs(*(uint16_t*)(pdu_data + 2));
                ss << "Address: " << addr << ", Value: " << (function_code == 5 ? (val == 0xFF00 ? "On" : "Off") : std::to_string(val));
                break;
            case 15: case 16:
                if (is_request) {
                    start_addr = ntohs(*(uint16_t*)(pdu_data));
                    quantity = ntohs(*(uint16_t*)(pdu_data + 2));
                    byte_count = pdu_data[4];
                    ss << "Start: " << start_addr << ", Quantity: " << quantity << ", " << (int)byte_count << " bytes";
                } else { // Response
                    start_addr = ntohs(*(uint16_t*)(pdu_data));
                    quantity = ntohs(*(uint16_t*)(pdu_data + 2));
                    ss << "Start: " << start_addr << ", Quantity: " << quantity;
                }
                break;
        }
    }
    info.details = ss.str();
    return info;
}


void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    auto current_time = std::chrono::steady_clock::now();

    for (auto& flow_pair : m_pending_requests) {
        std::vector<uint32_t> timed_out_acks;
        for (const auto& req_pair : flow_pair.second) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(current_time - req_pair.second.timestamp) > m_timeout) {
                timed_out_acks.push_back(req_pair.first);
            }
        }
        for (uint32_t ack : timed_out_acks) { flow_pair.second.erase(ack); }
    }

    if (!packet || header->caplen < sizeof(EthernetHeader)) return;
    int packet_len = header->caplen;

    // (수정) 타임스탬프 추출 및 포맷팅
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

    if (packet_len < sizeof(EthernetHeader) + sizeof(IPHeader)) return;
    const IPHeader* ip_header = (const IPHeader*)(packet + sizeof(EthernetHeader));
    const int ip_header_length = ip_header->hl * 4;
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

    if (ip_header->p == IPPROTO_TCP) {
        if (packet_len < sizeof(EthernetHeader) + ip_header_length + sizeof(TCPHeader)) return;
        const TCPHeader* tcp_header = (const TCPHeader*)((const u_char*)ip_header + ip_header_length);
        const int tcp_header_length = tcp_header->off * 4;
        const u_char* payload = (const u_char*)tcp_header + tcp_header_length;
        int payload_size = ntohs(ip_header->len) - (ip_header_length + tcp_header_length);
        uint16_t src_port = ntohs(tcp_header->sport);
        uint16_t dst_port = ntohs(tcp_header->dport);

        uint32_t seq_num = ntohl(tcp_header->seq);
        uint32_t ack_num = ntohl(tcp_header->ack);
        std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
        bool is_reply = false;

        if (m_pending_requests.count(flow_id) && m_pending_requests[flow_id].count(ack_num)) {
            is_reply = true;
            RequestInfo req_info = m_pending_requests[flow_id][ack_num];
            std::ofstream& out_stream = get_mapped_stream(req_info.protocol);

            if (out_stream.is_open() && req_info.protocol == "modbus_tcp") {
                ModbusInfo res_info = parse_modbus_payload(payload, payload_size, false);
                uint8_t func_code = payload[7];

                // (수정) 타임스탬프를 가장 앞에 추가
                out_stream << timestamp << "," << dst_ip_str << "," << dst_port << "," << src_ip_str << "," << src_port << ","
                           << "Response," << res_info.transaction_id << "," << res_info.protocol_id << ","
                           << res_info.length << "," << (int)res_info.unit_id << "," << (int)(func_code & 0x7F) << ",\""
                           << res_info.details << "\"\n";
            }
            m_pending_requests[flow_id].erase(ack_num);
        }

        if (payload_size > 0 && !is_reply) {
            if (is_modbus_signature(payload, payload_size)) {
                RequestInfo new_req;
                new_req.protocol = "modbus_tcp";
                new_req.timestamp = current_time;
                new_req.modbus_info = parse_modbus_payload(payload, payload_size, true);
                m_pending_requests[flow_id][seq_num + payload_size] = new_req;

                std::ofstream& out_stream = get_mapped_stream("modbus_tcp");
                if (out_stream.is_open()) {
                     ModbusInfo& req = new_req.modbus_info;
                     uint8_t func_code = payload[7];
                     // (수정) 타임스탬프를 가장 앞에 추가
                     out_stream << timestamp << "," << src_ip_str << "," << src_port << "," << dst_ip_str << "," << dst_port << ","
                                << "Query," << req.transaction_id << "," << req.protocol_id << ","
                                << req.length << "," << (int)req.unit_id << "," << (int)func_code << ",\""
                                << req.details << "\"\n";
                }
            }
        }
    }
}

