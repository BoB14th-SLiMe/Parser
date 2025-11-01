#include "ModbusParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <string>
#include <stdexcept>

ModbusParser::ModbusParser(AssetManager& assetManager)
    : m_assetManager(assetManager) {}

ModbusParser::~ModbusParser() {}

static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

struct ModbusRegister {
    std::string addr;
    std::string val;
};

struct ModbusParsedData {
    std::string fc;
    std::string err;
    std::string bc;
    std::string addr;
    std::string qty;
    std::string val;
    std::vector<ModbusRegister> regs;
};

ModbusParsedData parse_modbus_pdu_structured(const u_char* pdu, int pdu_len, bool is_response, const ModbusRequestInfo* req_info) {
    ModbusParsedData data;
    if (pdu_len < 1) return data;
    
    uint8_t function_code = pdu[0];
    const u_char* pdu_data = pdu + 1;
    int data_len = pdu_len - 1;

    data.fc = std::to_string(function_code & 0x7F);

    if (function_code & 0x80) {
        if (data_len >= 1) {
            data.err = std::to_string(pdu_data[0]);
        }
    } else {
        switch (function_code) {
            case 1: case 2:
            case 3: case 4: {
                if (is_response) {
                    if (data_len >= 1) {
                        uint8_t byte_count = pdu_data[0];
                        data.bc = std::to_string(byte_count);
                        
                        if (byte_count > 0 && data_len >= (1 + byte_count)) {
                            const u_char* reg_data = pdu_data + 1;
                            int num_registers = byte_count / 2;
                            uint16_t start_addr = req_info ? req_info->start_address : 0;
                            
                            for (int i = 0; i < num_registers; ++i) {
                                uint16_t reg_value = safe_ntohs(reg_data + (i * 2));
                                uint16_t reg_addr = start_addr + i;
                                data.regs.push_back({
                                    std::to_string(reg_addr),
                                    std::to_string(reg_value)
                                });
                            }
                        }
                    }
                } else {
                    if (data_len >= 4) {
                        uint16_t start_addr = safe_ntohs(pdu_data);
                        uint16_t quantity = safe_ntohs(pdu_data + 2);
                        data.addr = std::to_string(start_addr);
                        data.qty = std::to_string(quantity);
                    }
                }
                break;
            }
            case 5: case 6: {
                if (data_len >= 4) {
                    data.addr = std::to_string(safe_ntohs(pdu_data));
                    data.val = std::to_string(safe_ntohs(pdu_data + 2));
                }
                break;
            }
            case 15: case 16: {
                if (is_response) {
                    if (data_len >= 4) {
                        data.addr = std::to_string(safe_ntohs(pdu_data));
                        data.qty = std::to_string(safe_ntohs(pdu_data + 2));
                    }
                } else {
                    if (data_len >= 5) {
                        data.addr = std::to_string(safe_ntohs(pdu_data));
                        data.qty = std::to_string(safe_ntohs(pdu_data + 2));
                        data.bc = std::to_string(pdu_data[4]);
                    }
                }
                break;
            }
        }
    }
    return data;
}

std::string parse_modbus_pdu_json(const u_char* pdu, int pdu_len, bool is_response, const ModbusRequestInfo* req_info) {
    if (pdu_len < 1) return "{}";
    
    uint8_t function_code = pdu[0];
    const u_char* data = pdu + 1;
    int data_len = pdu_len - 1;

    std::stringstream ss;
    ss << "{";
    ss << "\"fc\":" << (int)(function_code & 0x7F);

    if (function_code & 0x80) {
        if (data_len >= 1) ss << ",\"err\":" << (int)data[0];
    } else {
        switch (function_code) {
            case 1: case 2:
            case 3: case 4: {
                if (is_response) {
                    if (data_len >= 1) {
                        uint8_t byte_count = data[0];
                        ss << ",\"bc\":" << (int)byte_count;
                        if (byte_count > 0 && data_len >= (1 + byte_count)) {
                            ss << ",\"regs\":{";
                            const u_char* reg_data = data + 1;
                            int num_registers = byte_count / 2;
                            uint16_t start_addr = req_info ? req_info->start_address : 0;
                            for (int i = 0; i < num_registers; ++i) {
                                if (i > 0) ss << ",";
                                uint16_t reg_addr = start_addr + i;
                                ss << "\"" << reg_addr << "\":"
                                   << safe_ntohs(reg_data + i * 2);
                            }
                            ss << "}";
                        }
                    }
                } else {
                    if (data_len >= 4) {
                        ss << ",\"addr\":" << safe_ntohs(data)
                           << ",\"qty\":" << safe_ntohs(data + 2);
                    }
                }
                break;
            }
            case 5: case 6: {
                if (data_len >= 4) {
                    ss << ",\"addr\":" << safe_ntohs(data)
                       << ",\"val\":" << safe_ntohs(data + 2);
                }
                break;
            }
            case 15: case 16: {
                if (is_response) {
                    if (data_len >= 4) {
                        ss << ",\"addr\":" << safe_ntohs(data)
                           << ",\"qty\":" << safe_ntohs(data + 2);
                    }
                } else {
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

std::string ModbusParser::getName() const { 
    return "modbus_tcp"; 
}

void ModbusParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,"
               << "tid,pdu.fc,pdu.err,pdu.bc,pdu.addr,pdu.qty,pdu.val,"
               << "pdu.regs.addr,pdu.regs.val,translated_addr,description,device\n";
}

bool ModbusParser::isProtocol(const PacketInfo& info) const {
    return info.protocol == IPPROTO_TCP &&
           (info.dst_port == 502 || info.src_port == 502 || 
            info.dst_port == 1000 || info.src_port == 1000) &&  // Power Meter 포트 추가
           info.payload_size >= 7 &&
           info.payload[2] == 0x00 &&
           info.payload[3] == 0x00;
}

void ModbusParser::parse(const PacketInfo& info) {
    uint16_t trans_id = safe_ntohs(info.payload);
    const u_char* pdu = info.payload + 7;
    int pdu_len = info.payload_size - 7;
    
    if (pdu_len < 1) return;

    // 서버 포트 판별 (502 또는 1000)
    bool is_request = (info.dst_port == 502 || info.dst_port == 1000);
    bool is_response = (info.src_port == 502 || info.src_port == 1000);
    
    std::string direction = is_request ? "request" : "response";
    std::string pdu_json;
    ModbusParsedData csv_data;
    ModbusRequestInfo* req_info_ptr = nullptr;

    // 서버와 클라이언트 IP/Port 결정
    std::string flow_key;
    std::string client_ip, server_ip;
    uint16_t client_port, server_port;
    
    if (info.src_port == 502 || info.src_port == 1000) {
        server_ip = info.src_ip;
        server_port = info.src_port;
        client_ip = info.dst_ip;
        client_port = info.dst_port;
    } else {
        server_ip = info.dst_ip;
        server_port = info.dst_port;
        client_ip = info.src_ip;
        client_port = info.src_port;
    }
    
    flow_key = client_ip + ":" + std::to_string(client_port) + "->" + 
               server_ip + ":" + std::to_string(server_port);

    // Transaction ID와 Function Code를 조합한 키 생성
    uint8_t current_fc = pdu[0] & 0x7F;
    uint32_t req_key = (static_cast<uint32_t>(trans_id) << 8) | current_fc;
    
    // 디바이스 정보 조회
    std::string device_name = m_assetManager.getDeviceName(server_ip);
    
    if (is_response) {
        if (m_pending_requests[flow_key].count(req_key)) {
            req_info_ptr = &m_pending_requests[flow_key][req_key];
        }
        
        pdu_json = parse_modbus_pdu_json(pdu, pdu_len, true, req_info_ptr);
        csv_data = parse_modbus_pdu_structured(pdu, pdu_len, true, req_info_ptr);
    } else {
        ModbusRequestInfo new_req;
        new_req.function_code = current_fc;
        
        if (pdu_len >= 3) {
            if ((new_req.function_code >= 1 && new_req.function_code <= 6) ||
                (new_req.function_code == 15 || new_req.function_code == 16)) {
                new_req.start_address = safe_ntohs(pdu + 1);
            }
        }
        
        m_pending_requests[flow_key][req_key] = new_req;
        pdu_json = parse_modbus_pdu_json(pdu, pdu_len, false, nullptr);
        csv_data = parse_modbus_pdu_structured(pdu, pdu_len, false, nullptr);
    }
    
    // JSONL 파일 쓰기
    std::stringstream details_ss_json;
    details_ss_json << R"({"tid":)" << trans_id << R"(,"pdu":)" << pdu_json << R"(})";
    writeJsonl(info, direction, details_ss_json.str());

    // CSV 파일 쓰기
    if (m_csv_stream && m_csv_stream->is_open()) {
        if (!csv_data.regs.empty()) {
            // 여러 레지스터: 각각 한 줄씩 (개선된 매핑 사용)
            for (const auto& reg : csv_data.regs) {
                std::string translated_addr;
                std::string description;
                
                try {
                    unsigned long reg_addr = std::stoul(reg.addr);
                    int fc = std::stoi(csv_data.fc);
                    
                    // === 개선된 레지스터 매핑 조회 ===
                    bool found = m_assetManager.getRegisterInfo(
                        server_ip, 
                        server_port, 
                        fc, 
                        reg_addr,
                        translated_addr,
                        description
                    );
                    
                    if (!found) {
                        // 매핑이 없으면 기본 변환
                        std::cout << "[DEBUG] No mapping found for " << server_ip 
                                  << ":" << server_port << " FC" << fc 
                                  << " Addr:" << reg_addr << std::endl;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[ERROR] Register mapping failed: " << e.what() << std::endl;
                    translated_addr = reg.addr;
                    description = "Parse Error";
                }

                std::stringstream ss;
                ss << info.timestamp << ","
                   << info.src_mac << "," << info.dst_mac << ","
                   << info.src_ip << "," << info.src_port << ","
                   << info.dst_ip << "," << info.dst_port << ","
                   << info.tcp_seq << "," << info.tcp_ack << "," 
                   << (int)info.tcp_flags << ","
                   << direction << ","
                   << trans_id << ","
                   << csv_data.fc << "," << csv_data.err << "," 
                   << csv_data.bc << ","
                   << "" << "," << "" << "," << "" << ","
                   << reg.addr << "," << reg.val << ","
                   << escape_csv(translated_addr) << ","
                   << escape_csv(description) << ","
                   << escape_csv(device_name) << "\n";
                
                *m_csv_stream << ss.str();
            }
        } else {
            // 단일 값 또는 요청
            std::string translated_addr;
            std::string description;
            
            if (!csv_data.addr.empty()) {
                try {
                    unsigned long reg_addr = std::stoul(csv_data.addr);
                    int fc = std::stoi(csv_data.fc);
                    
                    m_assetManager.getRegisterInfo(
                        server_ip, 
                        server_port, 
                        fc, 
                        reg_addr,
                        translated_addr, 
                        description
                    );
                } catch (const std::exception& e) {
                    translated_addr = csv_data.addr;
                    description = "Parse Error";
                }
            }

            std::stringstream ss;
            ss << info.timestamp << ","
               << info.src_mac << "," << info.dst_mac << ","
               << info.src_ip << "," << info.src_port << ","
               << info.dst_ip << "," << info.dst_port << ","
               << info.tcp_seq << "," << info.tcp_ack << "," 
               << (int)info.tcp_flags << ","
               << direction << ","
               << trans_id << ","
               << csv_data.fc << "," << csv_data.err << "," 
               << csv_data.bc << ","
               << csv_data.addr << "," << csv_data.qty << "," 
               << csv_data.val << ","
               << "" << "," << "" << ","
               << escape_csv(translated_addr) << ","
               << escape_csv(description) << ","
               << escape_csv(device_name) << "\n";
            
            *m_csv_stream << ss.str();
        }
    }
}