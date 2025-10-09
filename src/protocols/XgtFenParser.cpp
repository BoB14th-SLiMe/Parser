#include "XgtFenParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>

// --- Helper Functions ---
// FEnet 프로토콜은 Little-endian을 사용하므로, 관련 헬퍼 함수를 정의합니다.
static uint16_t safe_letohs(const u_char* ptr) {
    return (uint16_t)(ptr[0] | (ptr[1] << 8));
}

// 프로토콜 코드 값을 사람이 읽을 수 있는 문자열로 변환합니다.
// *** 수정: 실제 Little-endian 값으로 case 문을 변경 ***
static std::string get_command_name(uint16_t cmd) {
    switch(cmd) {
        case 0x0054: return "Read Request";
        case 0x0055: return "Read Response";
        case 0x0058: return "Write Request";
        case 0x0059: return "Write Response";
        default: return "Unknown Command";
    }
}

static std::string get_data_type_name(uint16_t type) {
    switch(type) {
        case 0x0000: return "Bit";
        case 0x0001: return "Byte";
        case 0x0002: return "Word";
        case 0x0003: return "DWord";
        case 0x0004: return "LWord";
        case 0x0014: return "Continuous (Block)";
        default: return "Unknown Type";
    }
}

// --- IProtocolParser Interface Implementation ---

std::string XgtFenParser::getName() const {
    return "xgt_fen";
}

void XgtFenParser::setOutputStream(std::ofstream* stream) {
    m_output_stream = stream;
}

bool XgtFenParser::isProtocol(const u_char* payload, int size) const {
    // FEnet Header (20 bytes) + 최소 Instruction (2 bytes) = 22 bytes
    if (size < 22) return false;
    // 시그니처 'LSIS-XGT' 확인
    return memcmp(payload, "LSIS-XGT", 8) == 0;
}

void XgtFenParser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;

    const u_char* header = info.payload;
    if (info.payload_size < 20) return;

    uint8_t frame_source = header[13];
    uint16_t invoke_id = safe_letohs(header + 14);
    uint16_t instruction_len = safe_letohs(header + 16);
    
    const u_char* pdu = header + 20;
    int pdu_len = info.payload_size - 20;

    if (pdu_len < 0 || (uint16_t)pdu_len < instruction_len) return; // Validate length

    // --- Response Processing (Server -> Client) ---
    if (frame_source == 0x11 && m_pending_requests[info.flow_id].count(invoke_id)) {
        XgtFenRequestInfo req_info = m_pending_requests[info.flow_id][invoke_id];
        uint16_t command = safe_letohs(pdu);
        
        std::string details_json = parse_pdu(pdu, pdu_len, false, &req_info);
        
        *m_output_stream << "{\"timestamp\":\"" << info.timestamp << "\",\"type\":\"" << get_command_name(command) << "\","
                       << "\"src_ip\":\"" << info.src_ip << "\",\"src_port\":" << info.src_port << ","
                       << "\"dst_ip\":\"" << info.dst_ip << "\",\"dst_port\":" << info.dst_port << ","
                       << "\"seq\":" << info.tcp_seq << ",\"ack\":" << info.tcp_ack << ",\"ip_len\":" << info.ip_len << ","
                       << "\"invoke_id\":" << invoke_id << ","
                       << "\"details\":" << details_json << "}\n";
        
        m_pending_requests[info.flow_id].erase(invoke_id);
    }
    // --- Request Processing (Client -> Server) ---
    else if (frame_source == 0x33) {
        XgtFenRequestInfo new_req;
        new_req.timestamp = std::chrono::steady_clock::now();
        new_req.invoke_id = invoke_id;
        
        if (pdu_len >= 4) {
             new_req.command = safe_letohs(pdu);
             new_req.data_type = safe_letohs(pdu + 2);
        }
        
        std::string details_json = parse_pdu(pdu, pdu_len, true, nullptr);
        m_pending_requests[info.flow_id][invoke_id] = new_req;
        
        *m_output_stream << "{\"timestamp\":\"" << info.timestamp << "\",\"type\":\"" << get_command_name(new_req.command) << "\","
                       << "\"src_ip\":\"" << info.src_ip << "\",\"src_port\":" << info.src_port << ","
                       << "\"dst_ip\":\"" << info.dst_ip << "\",\"dst_port\":" << info.dst_port << ","
                       << "\"seq\":" << info.tcp_seq << ",\"ack\":" << info.tcp_ack << ",\"ip_len\":" << info.ip_len << ","
                       << "\"invoke_id\":" << invoke_id << ","
                       << "\"details\":" << details_json << "}\n";
    }
}

std::string XgtFenParser::parse_pdu(const u_char* pdu, int pdu_len, bool is_request, const XgtFenRequestInfo* req_info) {
    if (pdu_len < 2) return "{}";

    std::stringstream ss;
    ss << "{";

    uint16_t command = safe_letohs(pdu);
    ss << "\"command\":\"" << get_command_name(command) << "\"";

    if (pdu_len < 4) {
        ss << "}";
        return ss.str();
    }
    uint16_t data_type = safe_letohs(pdu + 2);
    ss << ",\"data_type\":\"" << get_data_type_name(data_type) << "\"";

    const u_char* data = pdu + 4;
    int data_len = pdu_len - 4;

    // *** 수정: 실제 Little-endian 값으로 case 문을 변경 ***
    switch (command) {
        case 0x0054: // Read Request
        case 0x0058: // Write Request
        {
            if (data_len < 4) break;
            uint16_t block_count = safe_letohs(data + 2);
            ss << ",\"block_count\":" << block_count;

            if (data_type == 0x0014) { // Continuous Read/Write
                if (data_len < 6) break;
                const u_char* var_ptr = data + 4;
                uint16_t var_len = safe_letohs(var_ptr);
                if (var_len > 0 && data_len >= 6 + var_len) {
                    ss << ",\"variable\":{\"name\":\"" << std::string(reinterpret_cast<const char*>(var_ptr + 2), var_len) << "\"";
                    if(command == 0x0054){ // Continuous Read
                        uint16_t read_size = safe_letohs(var_ptr + 2 + var_len);
                        ss << ",\"read_bytes\":" << read_size << "}";
                    } else { // Continuous Write
                        uint16_t write_size = safe_letohs(var_ptr + 2 + var_len);
                        ss << ",\"write_bytes\":" << write_size;
                        ss << ",\"data\":\"";
                        std::stringstream hex_ss;
                        hex_ss << std::hex << std::setfill('0');
                        for(int i = 0; i < write_size; ++i) {
                             hex_ss << std::setw(2) << static_cast<int>(var_ptr[4 + var_len + i]);
                        }
                        ss << hex_ss.str() << "\"}";
                    }
                }
            } else { // Individual Read/Write
                ss << ",\"variables\":[";
                const u_char* var_ptr = data + 4;
                for (uint16_t i = 0; i < block_count; ++i) {
                    if ((var_ptr + 2) > (pdu + pdu_len)) break;
                    uint16_t var_len = safe_letohs(var_ptr);
                    if ((var_ptr + 2 + var_len) > (pdu + pdu_len)) break;
                    ss << (i > 0 ? "," : "") << "{\"name\":\"" << std::string(reinterpret_cast<const char*>(var_ptr + 2), var_len) << "\"}";
                    var_ptr += (2 + var_len);
                }
                ss << "]";
                 if (command == 0x0058) { // Individual Write also has data
                    ss << ",\"data\":[";
                    const u_char* data_ptr = var_ptr;
                     for (uint16_t i = 0; i < block_count; ++i) {
                        if ((data_ptr + 2) > (pdu + pdu_len)) break;
                        uint16_t data_size = safe_letohs(data_ptr);
                        if ((data_ptr + 2 + data_size) > (pdu + pdu_len)) break;
                        ss << (i > 0 ? "," : "") << "{\"value\":\"";
                         std::stringstream hex_ss;
                         hex_ss << std::hex << std::setfill('0');
                         for(int j = 0; j < data_size; ++j) {
                            hex_ss << std::setw(2) << static_cast<int>(data_ptr[2+j]);
                         }
                         ss << hex_ss.str() << "\"}";
                         data_ptr += (2 + data_size);
                     }
                    ss << "]";
                }
            }
            break;
        }
        case 0x0055: // Read Response
        case 0x0059: // Write Response
        {
            if (data_len < 4) break;
            uint16_t error_status = safe_letohs(data);
            if(error_status != 0) {
                 ss << ",\"error_status\":" << error_status;
                 ss << ",\"error_code\":" << (int)data[3];
                 break;
            }
            ss << ",\"error_status\":" << error_status;
            
            if (command == 0x0055) { // Read Response has data
                if (data_type == 0x0014) { // Continuous Read Response
                    uint16_t block_count = safe_letohs(data + 2);
                    uint16_t data_size = safe_letohs(data + 4);
                    ss << ",\"block_count\":" << block_count;
                    ss << ",\"byte_count\":" << data_size;
                    ss << ",\"data\":\"";
                    std::stringstream hex_ss;
                    hex_ss << std::hex << std::setfill('0');
                    for(int i = 0; i < data_size; ++i) {
                         hex_ss << std::setw(2) << static_cast<int>(data[6 + i]);
                    }
                    ss << hex_ss.str() << "\"";
                } else { // Individual Read Response
                    uint16_t block_count = safe_letohs(data + 2);
                    ss << ",\"block_count\":" << block_count;
                    ss << ",\"data\":[";
                    const u_char* data_ptr = data + 4;
                    for (uint16_t i = 0; i < block_count; ++i) {
                        if ((data_ptr + 2) > (pdu + pdu_len)) break;
                        uint16_t data_size = safe_letohs(data_ptr);
                        if ((data_ptr + 2 + data_size) > (pdu + pdu_len)) break;
                        ss << (i > 0 ? "," : "") << "{\"value\":\"";
                         std::stringstream hex_ss;
                         hex_ss << std::hex << std::setfill('0');
                         for(int j = 0; j < data_size; ++j) {
                            hex_ss << std::setw(2) << static_cast<int>(data_ptr[2+j]);
                         }
                         ss << hex_ss.str() << "\"}";
                        data_ptr += (2 + data_size);
                    }
                    ss << "]";
                }
            } else { // Write Response
                 uint16_t block_count = safe_letohs(data + 2);
                 ss << ",\"block_count\":" << block_count;
            }
            break;
        }
    }

    ss << "}";
    return ss.str();
}
