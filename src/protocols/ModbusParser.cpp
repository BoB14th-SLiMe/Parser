#include "ModbusParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

ModbusParser::~ModbusParser() {}

// --- Helper Functions ---
static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

// Optimized PDU Parser
std::string parse_pdu_optimized(const u_char* pdu, int pdu_len, const ModbusRequestInfo* req_info) {
    if (pdu_len < 1) return "{}";
    uint8_t function_code = pdu[0];
    const u_char* data = pdu + 1;
    int data_len = pdu_len - 1;

    std::stringstream ss;
    ss << "{";
    ss << "\"fc\":" << (int)(function_code & 0x7F);

    if (function_code > 0x80) { // Exception
        if (data_len >= 1) ss << ",\"err\":" << (int)data[0];
    } else {
        switch (function_code) {
            case 1: case 2: case 3: case 4: { // Read Coils/Inputs/Registers
                if (req_info) { // Response
                    if (data_len >= 1) ss << ",\"bc\":" << (int)data[0];
                } else { // Request
                    if (data_len >= 4) {
                        ss << ",\"addr\":" << safe_ntohs(data)
                           << ",\"qty\":" << safe_ntohs(data + 2);
                    }
                }
                break;
            }
            case 5: case 6: { // Write Single Coil/Register
                if (data_len >= 4) {
                     ss << ",\"addr\":" << safe_ntohs(data)
                        << ",\"val\":" << safe_ntohs(data + 2);
                }
                break;
            }
            case 15: case 16: { // Write Multiple Coils/Registers
                if (req_info) { // Response
                     if (data_len >= 4) {
                        ss << ",\"addr\":" << safe_ntohs(data)
                           << ",\"qty\":" << safe_ntohs(data + 2);
                    }
                } else { // Request
                    if (data_len >= 5) {
                        ss << ",\"addr\":" << safe_ntohs(data)
                           << ",\"qty\":" << safe_ntohs(data + 2)
                           << ",\"bc\":" << (int)data[4];
                    }
                }
                break;
            }
        }
    }
    ss << "}";
    return ss.str();
}

// --- IProtocolParser Interface Implementation ---
std::string ModbusParser::getName() const { return "modbus_tcp"; }
void ModbusParser::setOutputStream(std::ofstream* stream) { m_output_stream = stream; }
bool ModbusParser::isProtocol(const u_char* payload, int size) const {
    return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00;
}

void ModbusParser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;
    uint16_t trans_id = safe_ntohs(info.payload);
    const u_char* pdu = info.payload + 7;
    int pdu_len = info.payload_size - 7;
    if (pdu_len < 1) return;

    std::string details_json;

    if (m_pending_requests[info.flow_id].count(trans_id)) { // Response
        ModbusRequestInfo req_info = m_pending_requests[info.flow_id][trans_id];
        details_json = parse_pdu_optimized(pdu, pdu_len, &req_info);
        m_pending_requests[info.flow_id].erase(trans_id);
    } else { // Request
        ModbusRequestInfo new_req;
        new_req.function_code = pdu[0];
        m_pending_requests[info.flow_id][trans_id] = new_req;
        details_json = parse_pdu_optimized(pdu, pdu_len, nullptr);
    }
    
    *m_output_stream << "{\"ts\":\"" << info.timestamp << "\","
                   << "\"sip\":\"" << info.src_ip << "\",\"sp\":" << info.src_port << ","
                   << "\"dip\":\"" << info.dst_ip << "\",\"dp\":" << info.dst_port << ","
                   << "\"sq\":" << info.tcp_seq << ",\"ak\":" << info.tcp_ack << ",\"fl\":" << (int)info.tcp_flags << ","
                   << "\"tid\":" << trans_id << ",\"d\":" << details_json << "}\n";
}

