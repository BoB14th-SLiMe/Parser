#include "ModbusParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

// --- 추가: vtable 링커 오류 해결을 위한 명시적 소멸자 정의 ---
ModbusParser::~ModbusParser() {}

// Helper function to safely convert network byte order to host byte order for uint16_t
static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

// Optimized PDU Parser for Modbus
std::string parse_modbus_pdu_optimized(const u_char* pdu, int pdu_len, const ModbusRequestInfo* req_info) {
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
            case 1: case 2: // Read Coils / Read Discrete Inputs
            case 3: case 4: { // Read Holding Registers / Read Input Registers
                if (req_info) { // Response
                    if (data_len >= 1) {
                        uint8_t byte_count = data[0];
                        ss << ",\"bc\":" << (int)byte_count;
                        if (data_len > 1 && byte_count > 0) {
                            ss << ",\"regs\":{";
                            const u_char* reg_data = data + 1;
                            for (int i = 0; i < byte_count / 2; ++i) {
                                if ((i * 2 + 1) < byte_count) {
                                    ss << (i > 0 ? "," : "")
                                       << "\"" << (req_info->start_address + i) << "\":"
                                       << safe_ntohs(reg_data + i * 2);
                                }
                            }
                            ss << "}";
                        }
                    }
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

bool ModbusParser::isProtocol(const u_char* payload, int size) const {
    return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00;
}

void ModbusParser::parse(const PacketInfo& info) {
    uint16_t trans_id = safe_ntohs(info.payload);
    const u_char* pdu = info.payload + 7;
    int pdu_len = info.payload_size - 7;
    if (pdu_len < 1) return;

    std::string pdu_json;
    // --- 수정: direction 변수 추가 ---
    std::string direction;

    if (m_pending_requests[info.flow_id].count(trans_id)) { // Response
        direction = "response";
        ModbusRequestInfo req_info = m_pending_requests[info.flow_id][trans_id];
        pdu_json = parse_modbus_pdu_optimized(pdu, pdu_len, &req_info);
        m_pending_requests[info.flow_id].erase(trans_id);
    } else { // Request
        direction = "request";
        ModbusRequestInfo new_req;
        new_req.function_code = pdu[0];
        if ((new_req.function_code >= 1 && new_req.function_code <= 6) || new_req.function_code == 15 || new_req.function_code == 16) {
            if(pdu_len > 3) new_req.start_address = safe_ntohs(pdu + 1);
        }
        m_pending_requests[info.flow_id][trans_id] = new_req;
        pdu_json = parse_modbus_pdu_optimized(pdu, pdu_len, nullptr);
    }
    
    std::stringstream details_ss;
    details_ss << "{\"tid\":" << trans_id << ",\"pdu\":" << pdu_json << "}";
    
    // --- 수정: direction 인자 전달 ---
    writeOutput(info, details_ss.str(), direction);
}

