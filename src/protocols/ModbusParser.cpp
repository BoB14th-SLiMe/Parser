#include "ModbusParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector> // for std::vector
#include <string> // for std::to_string

ModbusParser::~ModbusParser() {}

// Helper function to safely convert network byte order to host byte order for uint16_t
static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

// --- (신규) CSV 레지스터 데이터용 구조체 ---
struct ModbusRegister {
    std::string addr;
    std::string val;
};

// --- (신규) CSV 출력을 위한 구조적 PDU 파서 ---
struct ModbusParsedData {
    std::string fc;
    std::string err;
    std::string bc;
    std::string addr;
    std::string qty;
    std::string val;
    std::vector<ModbusRegister> regs;
};

ModbusParsedData parse_modbus_pdu_structured(const u_char* pdu, int pdu_len, const ModbusRequestInfo* req_info) {
    ModbusParsedData data;
    if (pdu_len < 1) return data;
    uint8_t function_code = pdu[0];
    const u_char* pdu_data = pdu + 1;
    int data_len = pdu_len - 1;

    data.fc = std::to_string(function_code & 0x7F);

    if (function_code > 0x80) { // Exception
        if (data_len >= 1) data.err = std::to_string(pdu_data[0]);
    } else {
        switch (function_code) {
            case 1: case 2: // Read Coils / Read Discrete Inputs
            case 3: case 4: { // Read Holding Registers / Read Input Registers
                if (req_info) { // Response
                    if (data_len >= 1) {
                        uint8_t byte_count = pdu_data[0];
                        data.bc = std::to_string(byte_count);
                        if (data_len > 1 && byte_count > 0 && (function_code == 3 || function_code == 4)) {
                            const u_char* reg_data = pdu_data + 1;
                            for (int i = 0; i < byte_count / 2; ++i) {
                                if ((i * 2 + 1) < byte_count) {
                                    data.regs.push_back({
                                        std::to_string(req_info->start_address + i),
                                        std::to_string(safe_ntohs(reg_data + i * 2))
                                    });
                                }
                            }
                        }
                    }
                } else { // Request
                    if (data_len >= 4) {
                        data.addr = std::to_string(safe_ntohs(pdu_data));
                        data.qty = std::to_string(safe_ntohs(pdu_data + 2));
                    }
                }
                break;
            }
            case 5: case 6: { // Write Single Coil/Register
                if (data_len >= 4) {
                     data.addr = std::to_string(safe_ntohs(pdu_data));
                     data.val = std::to_string(safe_ntohs(pdu_data + 2));
                }
                break;
            }
            case 15: case 16: { // Write Multiple Coils/Registers
                if (req_info) { // Response
                     if (data_len >= 4) {
                        data.addr = std::to_string(safe_ntohs(pdu_data));
                        data.qty = std::to_string(safe_ntohs(pdu_data + 2));
                    }
                } else { // Request
                    if (data_len >= 5) {
                        data.addr = std::to_string(safe_ntohs(pdu_data));
                        data.qty = std::to_string(safe_ntohs(pdu_data + 2));
                        data.bc = std::to_string(pdu_data[4]);
                        // Python 스크립트는 Write Request의 레지스터는 펼치지 않으므로 여기서도 생략
                    }
                }
                break;
            }
        }
    }
    return data;
}


// --- (기존) JSONL 출력을 위한 PDU 파서 (이름 변경) ---
std::string parse_modbus_pdu_json(const u_char* pdu, int pdu_len, const ModbusRequestInfo* req_info) {
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

// --- 추가: Modbus용 CSV 헤더 (정규화 + 확장) ---
void ModbusParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,";
    // Normalized 'd' fields
    csv_stream << "tid,pdu.fc,pdu.err,pdu.bc,pdu.addr,pdu.qty,pdu.val,";
    // Exploded 'regs' fields
    csv_stream << "pdu.regs.addr,pdu.regs.val\n";
}


bool ModbusParser::isProtocol(const u_char* payload, int size) const {
    return size >= 7 && payload[2] == 0x00 && payload[3] == 0x00;
}

void ModbusParser::parse(const PacketInfo& info) {
    uint16_t trans_id = safe_ntohs(info.payload);
    const u_char* pdu = info.payload + 7;
    int pdu_len = info.payload_size - 7;
    if (pdu_len < 1) return;

    std::string pdu_json;
    std::string direction;
    ModbusParsedData csv_data;
    ModbusRequestInfo* req_info_ptr = nullptr;

    if (m_pending_requests[info.flow_id].count(trans_id)) { // Response
        direction = "response";
        req_info_ptr = &m_pending_requests[info.flow_id][trans_id];
        pdu_json = parse_modbus_pdu_json(pdu, pdu_len, req_info_ptr);
        csv_data = parse_modbus_pdu_structured(pdu, pdu_len, req_info_ptr);
        m_pending_requests[info.flow_id].erase(trans_id);
    } else { // Request
        direction = "request";
        ModbusRequestInfo new_req;
        new_req.function_code = pdu[0];
        if ((new_req.function_code >= 1 && new_req.function_code <= 4) || new_req.function_code == 15 || new_req.function_code == 16) {
            if(pdu_len > 3) new_req.start_address = safe_ntohs(pdu + 1);
        }
        m_pending_requests[info.flow_id][trans_id] = new_req;
        pdu_json = parse_modbus_pdu_json(pdu, pdu_len, nullptr);
        csv_data = parse_modbus_pdu_structured(pdu, pdu_len, nullptr);
    }
    
    // --- 1. JSONL 파일 쓰기 (기존 'd' 구조 유지) ---
    std::stringstream details_ss_json;
    details_ss_json << "{\"tid\":" << trans_id << ",\"pdu\":" << pdu_json << "}";
    writeJsonl(info, direction, details_ss_json.str());

    // --- 2. CSV 파일 쓰기 (정규화 + 확장) ---
    if (m_csv_stream && m_csv_stream->is_open()) {
        std::stringstream base_csv_line;
        base_csv_line << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                      << direction << ",";

        std::stringstream details_csv_line;
        details_csv_line << trans_id << ","
                         << csv_data.fc << "," << csv_data.err << "," << csv_data.bc << ","
                         << csv_data.addr << "," << csv_data.qty << "," << csv_data.val << ",";

        if (csv_data.regs.empty()) {
            // Write one line with empty item details
            *m_csv_stream << base_csv_line.str() << details_csv_line.str() << ",,\n";
        } else {
            // Explode logic: write one line per register
            for (const auto& reg : csv_data.regs) {
                *m_csv_stream << base_csv_line.str() << details_csv_line.str()
                              << reg.addr << "," << reg.val << "\n";
            }
        }
    }
}
