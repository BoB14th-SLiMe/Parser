#include "ModbusParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <string>

// 생성자
ModbusParser::ModbusParser(AssetManager& assetManager)
    : m_assetManager(assetManager) {}

ModbusParser::~ModbusParser() {}

// Helper function (기존과 동일)
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

// --- Modbus 오프셋 계산 헬퍼 ---
long getModbusOffset(const std::string& fc_str) {
    if (fc_str.empty()) return 0;
    try {
        int fc = std::stoi(fc_str);
        switch (fc) {
            case 0: return 1;
            case 1: return 10001;
            case 3: return 30001;
            case 4: return 40001;
            default: return 0;
        }
    } catch (const std::exception& e) {
        return 0;
    }
}

// --- IProtocolParser Interface Implementation ---
std::string ModbusParser::getName() const { return "modbus_tcp"; }

// --- 수정: Modbus용 CSV 헤더에 description 추가 ---
void ModbusParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,"
               << "tid,pdu.fc,pdu.err,pdu.bc,pdu.addr,pdu.qty,pdu.val,"
               << "pdu.regs.addr,pdu.regs.val,translated_addr,description\n";
}

bool ModbusParser::isProtocol(const PacketInfo& info) const {
    // Modbus TCP는 TCP 프로토콜을 사용하고 포트 502를 사용합니다.
    // 또한, Modbus ADU의 프로토콜 식별자(MBAP Header의 3, 4번째 바이트)가 0x0000이어야 합니다.
    return info.protocol == IPPROTO_TCP &&
           (info.dst_port == 502 || info.src_port == 502) &&
           info.payload_size >= 7 &&
           info.payload[2] == 0x00 &&
           info.payload[3] == 0x00;
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
    details_ss_json << R"({"tid":)" << trans_id << R"(,"pdu":)" << pdu_json << R"(})";
    writeJsonl(info, direction, details_ss_json.str());

    // --- 2. CSV 파일 쓰기 ---
    if (m_csv_stream && m_csv_stream->is_open()) {
        // 여러 레지스터를 포함하는 응답의 경우 여러 줄로 나눔
        if (!csv_data.regs.empty()) {
            for (const auto& reg : csv_data.regs) {
                std::string translated_addr = m_assetManager.translateModbusAddress(csv_data.fc, std::stoul(reg.addr));
                
                // DEBUG: Print all tags and the lookup key
                // m_assetManager.printAllTags();
                // std::cout << "Looking up: " << translated_addr << std::endl;

                std::string description = m_assetManager.getDescription(translated_addr);

                *m_csv_stream << info.timestamp << ","
                              << info.src_mac << "," << info.dst_mac << ","
                              << info.src_ip << "," << info.src_port << ","
                              << info.dst_ip << "," << info.dst_port << ","
                              << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                              << direction << ","
                              << trans_id << ","
                              << csv_data.fc << "," << csv_data.err << "," << csv_data.bc << ","
                              << "" << "," << "" << "," << "" << "," // pdu.addr, pdu.qty, pdu.val (N/A for multi-reg)
                              << reg.addr << "," << reg.val << ","
                              << escape_csv(translated_addr) << ","
                              << escape_csv(description) << "\n";
            }
        } else {
            // 단일 값 또는 요청
            std::string translated_addr = m_assetManager.translateModbusAddress(csv_data.fc, csv_data.addr.empty() ? 0 : std::stoul(csv_data.addr));
            std::string description = m_assetManager.getDescription(translated_addr);

            *m_csv_stream << info.timestamp << ","
                          << info.src_mac << "," << info.dst_mac << ","
                          << info.src_ip << "," << info.src_port << ","
                          << info.dst_ip << "," << info.dst_port << ","
                          << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                          << direction << ","
                          << trans_id << ","
                          << csv_data.fc << "," << csv_data.err << "," << csv_data.bc << ","
                          << csv_data.addr << "," << csv_data.qty << "," << csv_data.val << ","
                          << "" << "," << "" << "," // pdu.regs.* (N/A for single value)
                          << escape_csv(translated_addr) << ","
                          << escape_csv(description) << "\n";
        }
    }
}