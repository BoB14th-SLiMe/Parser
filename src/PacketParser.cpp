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
}

std::ofstream& PacketParser::get_mapped_stream(const std::string& protocol) {
    if (m_mapped_protocol_streams.find(protocol) == m_mapped_protocol_streams.end()) {
        std::string filename = m_output_dir + protocol + "_mapped.jsonl";
        m_mapped_protocol_streams[protocol].open(filename);
    }
    return m_mapped_protocol_streams[protocol];
}

std::string PacketParser::get_canonical_flow_id(const std::string& ip1_str, uint16_t port1, const std::string& ip2_str, uint16_t port2) {
    std::string ip1 = ip1_str, ip2 = ip2_str;
    if (ip1 > ip2 || (ip1 == ip2 && port1 > port2)) {
        std::swap(ip1, ip2);
        std::swap(port1, port2);
    }
    return ip1 + ":" + std::to_string(port1) + "-" + ip2 + ":" + std::to_string(port2);
}

bool PacketParser::is_modbus_signature(const u_char* payload, int size) {
    return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00;
}

// 버퍼에서 16비트 네트워크 오더 값을 안전하게 읽는 헬퍼 함수
uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

// Modbus Function Code 이름을 문자열로 반환하는 함수
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

// Wireshark 로직을 기반으로 재작성된 PDU 파싱 함수
std::string PacketParser::parse_modbus_pdu(const u_char* pdu, int pdu_len, bool is_request, const ModbusRequestInfo* req_info) {
    if (pdu_len < 1) return "{}";

    uint8_t function_code = pdu[0];
    const u_char* data = pdu + 1;
    int data_len = pdu_len - 1;

    std::stringstream ss;
    ss << "{";
    ss << "\"function\":\"" << get_modbus_function_name(function_code & 0x7F) << "\"";

    if (function_code > 0x80) { // 예외 응답
        if (data_len >= 1) {
            ss << ",\"exception_code\":" << (int)data[0];
        }
    } else if (is_request) { // --- 요청 파싱 ---
        switch (function_code) {
            case 1: case 2: case 3: case 4: {
                if (data_len >= 4) {
                    ss << ",\"start_address\":" << safe_ntohs(data)
                       << ",\"quantity\":" << safe_ntohs(data + 2);
                }
                break;
            }
            case 5: case 6: {
                if (data_len >= 4) {
                    ss << ",\"address\":" << safe_ntohs(data)
                       << ",\"value\":" << safe_ntohs(data + 2);
                }
                break;
            }
            case 15: case 16: {
                if (data_len >= 5) {
                    uint16_t start_addr = safe_ntohs(data);
                    uint16_t quantity = safe_ntohs(data + 2);
                    uint8_t byte_count = data[4];
                    ss << ",\"start_address\":" << start_addr
                       << ",\"quantity\":" << quantity
                       << ",\"byte_count\":" << (int)byte_count;
                    
                    if (function_code == 16 && byte_count > 0 && (size_t)data_len >= 5 + byte_count) {
                        ss << ",\"registers\":[";
                        for (int i = 0; i < quantity; ++i) {
                            if ((size_t)(5 + i * 2 + 2) <= (size_t)data_len) {
                                ss << (i > 0 ? "," : "")
                                   << "{\"register\":" << (start_addr + i)
                                   << ",\"value\":" << safe_ntohs(data + 5 + i * 2) << "}";
                            }
                        }
                        ss << "]";
                    }
                }
                break;
            }
        }
    } else { // --- 응답 파싱 ---
        switch (function_code) {
            case 1: case 2: case 3: case 4: {
                if (data_len >= 1) {
                    uint8_t byte_count = data[0];
                    ss << ",\"byte_count\":" << (int)byte_count;
                    if (byte_count > 0 && req_info && (size_t)data_len >= 1 + byte_count) {
                        ss << ",\"registers\":[";
                        for (int i = 0; i < req_info->quantity; ++i) {
                            if ((size_t)(1 + i * 2 + 2) <= (size_t)data_len) {
                                ss << (i > 0 ? "," : "")
                                   << "{\"register\":" << (req_info->start_address + i)
                                   << ",\"value\":" << safe_ntohs(data + 1 + i * 2) << "}";
                            }
                        }
                        ss << "]";
                    }
                }
                break;
            }
            case 5: case 6: case 15: case 16: {
                if (data_len >= 4) {
                    ss << ",\"start_address\":" << safe_ntohs(data)
                       << ",\"quantity\":" << safe_ntohs(data + 2);
                }
                break;
            }
        }
    }
    ss << "}";
    return ss.str();
}

void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    auto current_time = std::chrono::steady_clock::now();

    for (auto& flow_pair : m_pending_requests_modbus) {
        std::vector<uint16_t> timed_out_trans_ids;
        for (const auto& req_pair : flow_pair.second) {
            if (std::chrono::duration_cast<std::chrono::milliseconds>(current_time - req_pair.second.timestamp) > m_timeout) {
                timed_out_trans_ids.push_back(req_pair.first);
            }
        }
        for (uint16_t trans_id : timed_out_trans_ids) { flow_pair.second.erase(trans_id); }
    }

    if (!packet || header->caplen < sizeof(EthernetHeader)) return;
    int packet_len = header->caplen;

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
        if (packet_len < (sizeof(EthernetHeader) + ip_header_length + sizeof(TCPHeader))) return;
        
        const TCPHeader* tcp_header = (const TCPHeader*)((const u_char*)ip_header + ip_header_length);
        const int tcp_header_length = tcp_header->off * 4;
        const u_char* payload = (const u_char*)tcp_header + tcp_header_length;
        int payload_size = ntohs(ip_header->len) - (ip_header_length + tcp_header_length);
        
        uint16_t src_port = ntohs(tcp_header->sport);
        uint16_t dst_port = ntohs(tcp_header->dport);
        
        if (payload_size > 0 && is_modbus_signature(payload, payload_size)) {
            std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
            uint16_t trans_id = safe_ntohs(payload);

            const u_char* pdu = payload + 7;
            int pdu_len = payload_size - 7;
            if (pdu_len < 1) return;

            // --- 응답 처리 (Transaction ID 기반) ---
            if (m_pending_requests_modbus[flow_id].count(trans_id)) {
                RequestInfo req_info = m_pending_requests_modbus[flow_id][trans_id];
                
                // 요청과 응답의 Function Code가 일치하는지 확인
                if ((pdu[0] & 0x7F) == req_info.modbus_info.function_code) {
                    std::string details_json = parse_modbus_pdu(pdu, pdu_len, false, &req_info.modbus_info);
                    std::ofstream& out_stream = get_mapped_stream("modbus_tcp");
                    if (out_stream.is_open()) {
                        out_stream << "{\"timestamp\":\"" << timestamp << "\",\"type\":\"Response\","
                                   << "\"src_ip\":\"" << src_ip_str << "\",\"src_port\":" << src_port << ","
                                   << "\"dst_ip\":\"" << dst_ip_str << "\",\"dst_port\":" << dst_port << ","
                                   << "\"trans_id\":" << trans_id << ","
                                   << "\"proto_id\":" << safe_ntohs(payload + 2) << ","
                                   << "\"length\":" << safe_ntohs(payload + 4) << ","
                                   << "\"unit_id\":" << (int)payload[6] << ","
                                   << "\"func_code\":" << (int)(pdu[0] & 0x7F) << ","
                                   << "\"details\":" << details_json << "}\n";
                    }
                }
                m_pending_requests_modbus[flow_id].erase(trans_id);
            } 
            // --- 요청 처리 ---
            else {
                RequestInfo new_req;
                new_req.protocol = "modbus_tcp";
                new_req.timestamp = current_time;
                
                uint8_t func_code = pdu[0];
                new_req.modbus_info.transaction_id = trans_id;
                new_req.modbus_info.function_code = func_code;

                switch(func_code) {
                    case 1: case 2: case 3: case 4:
                        if (pdu_len >= 5) {
                            new_req.modbus_info.start_address = safe_ntohs(pdu + 1);
                            new_req.modbus_info.quantity = safe_ntohs(pdu + 3);
                        }
                        break;
                    case 15: case 16:
                        if (pdu_len >= 5) {
                           new_req.modbus_info.start_address = safe_ntohs(pdu + 1);
                           new_req.modbus_info.quantity = safe_ntohs(pdu + 3);
                        }
                        break;
                }

                std::string details_json = parse_modbus_pdu(pdu, pdu_len, true, nullptr);
                m_pending_requests_modbus[flow_id][trans_id] = new_req;

                std::ofstream& out_stream = get_mapped_stream("modbus_tcp");
                if (out_stream.is_open()) {
                     out_stream << "{\"timestamp\":\"" << timestamp << "\",\"type\":\"Query\","
                                << "\"src_ip\":\"" << src_ip_str << "\",\"src_port\":" << src_port << ","
                                << "\"dst_ip\":\"" << dst_ip_str << "\",\"dst_port\":" << dst_port << ","
                                << "\"trans_id\":" << trans_id << ","
                                << "\"proto_id\":" << safe_ntohs(payload + 2) << ","
                                << "\"length\":" << safe_ntohs(payload + 4) << ","
                                << "\"unit_id\":" << (int)payload[6] << ","
                                << "\"func_code\":" << (int)func_code << ","
                                << "\"details\":" << details_json << "}\n";
                }
            }
        }
    }
}

