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

// --- Signature Checkers ---
bool PacketParser::is_modbus_signature(const u_char* payload, int size) {
    return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00;
}

bool PacketParser::is_s7comm_signature(const u_char* payload, int size) {
    // TPKT (4) + COTP (3) + S7 Header (10) = min 17 bytes for job
    if (size < 17) return false;
    // TPKT version 3
    if (payload[0] != 0x03) return false;
    // COTP DT Data
    if (payload[5] != 0xf0) return false;
    // S7 Protocol ID
    if (payload[7] != 0x32) return false;
    return true;
}


// --- Helper Functions ---
uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

uint32_t s7_addr_to_int(const u_char* ptr) {
    // S7 address is 3 bytes, big-endian
    return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
}

// --- Modbus Parser ---
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

std::string PacketParser::parse_modbus_pdu(const u_char* pdu, int pdu_len, bool is_request, const ModbusRequestInfo* req_info) {
    if (pdu_len < 1) return "{}";

    uint8_t function_code = pdu[0];
    const u_char* data = pdu + 1;
    int data_len = pdu_len - 1;

    std::stringstream ss;
    ss << "{";
    ss << "\"function\":\"" << get_modbus_function_name(function_code & 0x7F) << "\"";

    if (function_code > 0x80) { // Exception Response
        if (data_len >= 1) {
            ss << ",\"exception_code\":" << (int)data[0];
        }
    } else if (is_request) { // --- Request Parsing ---
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
    } else { // --- Response Parsing ---
        switch (function_code) {
            case 1: case 2: case 3: case 4: {
                if (data_len >= 1) {
                    uint8_t byte_count = data[0];
                    ss << ",\"byte_count\":" << (int)byte_count;
                    if (byte_count > 0 && req_info && (size_t)data_len >= 1 + byte_count) {
                        ss << ",\"registers\":[";
                        for (int i = 0; i < req_info->quantity; ++i) {
                            if ((size_t)(1 + i * 2 + 2) <= (size_t)(1 + byte_count)) {
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


// --- S7comm Parser ---
std::string get_s7comm_rosctr_name(uint8_t r) {
    switch(r) {
        case 0x01: return "Job";
        case 0x02: return "Ack";
        case 0x03: return "Ack_Data";
        case 0x07: return "Userdata";
        default: return "Unknown";
    }
}

std::string get_s7comm_param_function_name(uint8_t f) {
     switch(f) {
        case 0x00: return "CPU services";
        case 0xF0: return "Setup communication";
        case 0x04: return "Read Var";
        case 0x05: return "Write Var";
        default: return "Unknown";
    }
}

std::string get_s7comm_area_name(uint8_t a) {
    switch(a) {
        case 0x81: return "Inputs";
        case 0x82: return "Outputs";
        case 0x83: return "Flags";
        case 0x84: return "Data blocks";
        case 0x1c: return "S7 timers";
        case 0x1d: return "S7 counters";
        default: return "Unknown";
    }
}

std::string PacketParser::parse_s7comm_pdu(const u_char* s7pdu, int s7pdu_len, bool is_request, const S7CommRequestInfo* req_info) {
    if (s7pdu_len < 10) return "{}";

    std::stringstream ss;
    ss << "{";

    uint8_t rosctr = s7pdu[1];
    uint16_t param_len = safe_ntohs(s7pdu + 6);
    uint16_t data_len = safe_ntohs(s7pdu + 8);
    const u_char* param = s7pdu + (rosctr == 2 || rosctr == 3 ? 12 : 10);
    const u_char* data = param + param_len;

    ss << "\"rosctr\":\"" << get_s7comm_rosctr_name(rosctr) << "\"";
    
    if(param_len > 0) {
        ss << ",\"parameter\":{";
        uint8_t func = param[0];
        ss << "\"function\":\"" << get_s7comm_param_function_name(func) << "\"";
        if (func == 0x04 || func == 0x05) { // Read/Write Var
            uint8_t item_count = param[1];
            ss << ",\"item_count\":" << (int)item_count;
            if (item_count > 0) {
                ss << ",\"items\":[";
                const u_char* item_ptr = param + 2;
                for(int i = 0; i < item_count; ++i) {
                    uint8_t syntax_id = item_ptr[2];
                    if (syntax_id == 0x10) { // S7_ANY format
                        uint16_t length = safe_ntohs(item_ptr + 4);
                        uint16_t db_num = safe_ntohs(item_ptr + 6);
                        uint8_t area = item_ptr[8];
                        uint32_t addr = s7_addr_to_int(item_ptr + 9);
                        
                        ss << (i > 0 ? "," : "") << "{";
                        ss << "\"area\":\"" << get_s7comm_area_name(area) << "\"";
                        if (area == 0x84) ss << ",\"db_number\":" << db_num;
                        ss << ",\"start_address\":" << (addr >> 3) << ",\"bit_offset\":" << (addr & 7);
                        ss << ",\"amount\":" << length;
                        ss << "}";
                    }
                    item_ptr += 12; // Move to next item
                }
                ss << "]";
            }
        }
        ss << "}";
    }

    if(data_len > 0) {
        ss << ",\"data\":{";
        if (rosctr == 3 && req_info) { // Ack_Data for Read Var
            uint8_t item_count = req_info->items.size();
            ss << "\"item_count\":" << (int)item_count;
            if (item_count > 0) ss << ",\"items\":[";
            const u_char* data_item_ptr = data;
            for(size_t i = 0; i < item_count; ++i) {
                uint8_t return_code = data_item_ptr[0];
                ss << (i > 0 ? "," : "") << "{";
                ss << "\"return_code\":" << (int)return_code;
                if (return_code == 0xff) { // Success
                    uint16_t read_len = safe_ntohs(data_item_ptr + 2);
                    ss << ",\"read_length\":" << read_len;
                    ss << ",\"value\":\"";
                    std::stringstream hex_ss;
                    hex_ss << std::hex << std::setfill('0');
                    for (int j = 0; j < read_len; ++j) {
                        hex_ss << std::setw(2) << static_cast<int>(data_item_ptr[4+j]);
                    }
                    ss << hex_ss.str() << "\"";
                    data_item_ptr += 4 + read_len + (read_len % 2); // align to 2 bytes
                } else {
                     data_item_ptr += 1;
                }
                ss << "}";
            }
             if (item_count > 0) ss << "]";
        }
        ss << "}";
    }

    ss << "}";
    return ss.str();
}

void PacketParser::parse(const struct pcap_pkthdr* header, const u_char* packet) {
    auto current_time = std::chrono::steady_clock::now();

    // Timeout logic for Modbus and S7comm...
    // ...

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
        std::string flow_id = get_canonical_flow_id(src_ip_str, src_port, dst_ip_str, dst_port);
        
        // --- S7comm Processing ---
        if (is_s7comm_signature(payload, payload_size)) {
            const u_char* s7_pdu = payload + 7; // Skip TPKT+COTP
            int s7_pdu_len = payload_size - 7;
            uint16_t pdu_ref = safe_ntohs(s7_pdu + 4);
            uint8_t rosctr = s7_pdu[1];

            // --- S7comm Response ---
            if ((rosctr == 0x02 || rosctr == 0x03) && m_pending_requests_s7comm[flow_id].count(pdu_ref)) {
                RequestInfo req_info = m_pending_requests_s7comm[flow_id][pdu_ref];
                
                std::string details_json = parse_s7comm_pdu(s7_pdu, s7_pdu_len, false, &req_info.s7comm_info);
                
                std::ofstream& out_stream = get_mapped_stream("s7comm");
                if (out_stream.is_open()) {
                     out_stream << "{\"timestamp\":\"" << timestamp << "\",\"type\":\"" << get_s7comm_rosctr_name(rosctr) << "\","
                                << "\"src_ip\":\"" << src_ip_str << "\",\"src_port\":" << src_port << ","
                                << "\"dst_ip\":\"" << dst_ip_str << "\",\"dst_port\":" << dst_port << ","
                                << "\"pdu_ref\":" << pdu_ref << ","
                                << "\"details\":" << details_json << "}\n";
                }
                m_pending_requests_s7comm[flow_id].erase(pdu_ref);
            }
            // --- S7comm Request ---
            else if (rosctr == 0x01) { // Job
                RequestInfo new_req;
                new_req.protocol = "s7comm";
                new_req.timestamp = current_time;
                new_req.s7comm_info.pdu_ref = pdu_ref;
                
                uint16_t param_len = safe_ntohs(s7_pdu + 6);
                if (param_len > 0) {
                    const u_char* param = s7_pdu + 10;
                    new_req.s7comm_info.function_code = param[0];
                    if (new_req.s7comm_info.function_code == 0x04 || new_req.s7comm_info.function_code == 0x05) {
                        uint8_t item_count = param[1];
                        const u_char* item_ptr = param + 2;
                        for(int i=0; i < item_count; ++i) {
                             S7CommItem item;
                             item.transport_size = item_ptr[3];
                             item.length = safe_ntohs(item_ptr+4);
                             item.db_number = safe_ntohs(item_ptr+6);
                             item.area = item_ptr[8];
                             item.address = s7_addr_to_int(item_ptr+9);
                             new_req.s7comm_info.items.push_back(item);
                             item_ptr += 12;
                        }
                    }
                }

                std::string details_json = parse_s7comm_pdu(s7_pdu, s7_pdu_len, true, nullptr);
                m_pending_requests_s7comm[flow_id][pdu_ref] = new_req;

                std::ofstream& out_stream = get_mapped_stream("s7comm");
                if (out_stream.is_open()) {
                     out_stream << "{\"timestamp\":\"" << timestamp << "\",\"type\":\"Job\","
                                << "\"src_ip\":\"" << src_ip_str << "\",\"src_port\":" << src_port << ","
                                << "\"dst_ip\":\"" << dst_ip_str << "\",\"dst_port\":" << dst_port << ","
                                << "\"pdu_ref\":" << pdu_ref << ","
                                << "\"details\":" << details_json << "}\n";
                }
            }
        }
        // --- Modbus Processing ---
        else if (is_modbus_signature(payload, payload_size)) {
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

