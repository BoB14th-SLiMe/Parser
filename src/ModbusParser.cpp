#include "ModbusParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

// --- Helper Functions ---
static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

static std::string get_modbus_function_name(uint8_t fc) {
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

// --- IProtocolParser Interface Implementation ---

std::string ModbusParser::getName() const {
    return "modbus_tcp";
}

void ModbusParser::setOutputStream(std::ofstream* stream) {
    m_output_stream = stream;
}

bool ModbusParser::isProtocol(const u_char* payload, int size) const {
    // Check for Modbus TCP signature: Protocol ID is 0x0000
    return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00;
}

void ModbusParser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;

    uint16_t trans_id = safe_ntohs(info.payload);
    const u_char* pdu = info.payload + 7;
    int pdu_len = info.payload_size - 7;
    if (pdu_len < 1) return;

    // --- Response Processing (based on Transaction ID) ---
    if (m_pending_requests[info.flow_id].count(trans_id)) {
        ModbusRequestInfo req_info = m_pending_requests[info.flow_id][trans_id];
        
        if ((pdu[0] & 0x7F) == req_info.function_code) {
            std::string details_json = parse_pdu(pdu, pdu_len, false, &req_info);
            *m_output_stream << "{\"timestamp\":\"" << info.timestamp << "\",\"type\":\"Response\","
                           << "\"src_ip\":\"" << info.src_ip << "\",\"src_port\":" << info.src_port << ","
                           << "\"dst_ip\":\"" << info.dst_ip << "\",\"dst_port\":" << info.dst_port << ","
                           << "\"seq\":" << info.tcp_seq << ",\"ack\":" << info.tcp_ack << ",\"ip_len\":" << info.ip_len << ","
                           << "\"trans_id\":" << trans_id << ","
                           << "\"details\":" << details_json << "}\n";
        }
        m_pending_requests[info.flow_id].erase(trans_id);
    } 
    // --- Request Processing ---
    else {
        ModbusRequestInfo new_req;
        new_req.timestamp = std::chrono::steady_clock::now();
        uint8_t func_code = pdu[0];
        new_req.transaction_id = trans_id;
        new_req.function_code = func_code;

        switch(func_code) {
            case 1: case 2: case 3: case 4:
            case 15: case 16:
                if (pdu_len >= 5) {
                    new_req.start_address = safe_ntohs(pdu + 1);
                    new_req.quantity = safe_ntohs(pdu + 3);
                }
                break;
        }

        std::string details_json = parse_pdu(pdu, pdu_len, true, nullptr);
        m_pending_requests[info.flow_id][trans_id] = new_req;
        
        *m_output_stream << "{\"timestamp\":\"" << info.timestamp << "\",\"type\":\"Query\","
                       << "\"src_ip\":\"" << info.src_ip << "\",\"src_port\":" << info.src_port << ","
                       << "\"dst_ip\":\"" << info.dst_ip << "\",\"dst_port\":" << info.dst_port << ","
                       << "\"seq\":" << info.tcp_seq << ",\"ack\":" << info.tcp_ack << ",\"ip_len\":" << info.ip_len << ","
                       << "\"trans_id\":" << trans_id << ","
                       << "\"details\":" << details_json << "}\n";
    }
}


std::string ModbusParser::parse_pdu(const u_char* pdu, int pdu_len, bool is_request, const ModbusRequestInfo* req_info) {
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
            case 1: case 2: case 3: case 4: { // Read Coils/Inputs/Registers
                if (data_len >= 4) {
                    ss << ",\"start_address\":" << safe_ntohs(data)
                       << ",\"quantity\":" << safe_ntohs(data + 2);
                }
                break;
            }
            case 5: case 6: { // Write Single Coil/Register
                if (data_len >= 4) {
                    ss << ",\"address\":" << safe_ntohs(data)
                       << ",\"value\":" << safe_ntohs(data + 2);
                }
                break;
            }
            case 15: case 16: { // Write Multiple Coils/Registers
                if (data_len >= 5) {
                    ss << ",\"start_address\":" << safe_ntohs(data)
                       << ",\"quantity\":" << safe_ntohs(data + 2)
                       << ",\"byte_count\":" << (int)data[4];
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
                            // Check if there's enough data for the next 2-byte register value
                            if ((size_t)(i * 2 + 2) <= (size_t)byte_count) {
                                ss << (i > 0 ? "," : "")
                                   << "{\"register\":" << (req_info->start_address + i)
                                   << ",\"value\":" << safe_ntohs(data + 1 + i * 2) << "}";
                            } else {
                                break; // Stop if payload data is shorter than expected
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

