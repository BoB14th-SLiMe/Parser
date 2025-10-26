#include "XgtFenParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>

// --- Helper Functions ---

// Little-Endian 2 bytes to short
static uint16_t safe_letohs(const u_char* ptr) {
    return (uint16_t)(ptr[0] | (ptr[1] << 8));
}

// Helper to append hex data to stringstream
static void append_hex_data(std::stringstream& ss, const u_char* data, int len) {
    ss << "\"";
    for(int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    ss << "\"";
}

// --- (기존) JSONL 출력을 위한 PDU 파서 (수정됨) ---
std::string parse_fenet_pdu_json(const u_char* pdu, int pdu_len, const XgtFenRequestInfo* req_info) {
    if (pdu_len < 2) return "{}";
    std::stringstream ss;
    ss << "{";

    uint16_t command_code = safe_letohs(pdu);
    uint16_t datatype_code = (pdu_len >= 4) ? safe_letohs(pdu + 2) : 0;

    ss << "\"cmd\":" << command_code;
    if (pdu_len >= 4) {
        ss << ",\"dt\":" << datatype_code;
    }

    const u_char* data_area = pdu + 4;
    int data_area_len = pdu_len - 4;
    bool is_response = (req_info != nullptr); // 응답인지 여부 (간단한 추정)

    switch (command_code) {
        case 0x0054: // Read Request
        case 0x0058: // Write Request
        {
            if (data_area_len < 4) break;
            uint16_t block_count = safe_letohs(data_area + 2);
            ss << ",\"bc\":" << block_count;

            const u_char* var_ptr = data_area + 4;
            int remaining_len = data_area_len - 4;

            if (datatype_code == 0x0014) { // Continuous Block
                if (remaining_len < 2) break;
                uint16_t var_len = safe_letohs(var_ptr);
                if (remaining_len >= 2 + var_len) {
                    ss << ",\"var\":{\"nm\":\"" << std::string(reinterpret_cast<const char*>(var_ptr + 2), var_len) << "\"";
                    if(command_code == 0x0054) { // Read
                        if (remaining_len >= 4 + var_len) {
                           ss << ",\"len\":" << safe_letohs(var_ptr + 2 + var_len);
                        }
                    } else { // Write
                         if (remaining_len >= 4 + var_len) {
                            uint16_t data_size = safe_letohs(var_ptr + 2 + var_len);
                            ss << ",\"len\":" << data_size;
                            if (remaining_len >= 4 + var_len + data_size) {
                                ss << ",\"data\":";
                                append_hex_data(ss, var_ptr + 4 + var_len, data_size);
                            }
                        }
                    }
                    ss << "}";
                }
            }
            break;
        }
        case 0x0055: // Read Response
        case 0x0059: // Write Response
        {
            if (data_area_len < 4) break;
            uint16_t error_status = safe_letohs(data_area);
            ss << ",\"err\":" << error_status;

            if (error_status == 0xFFFF && data_area_len >= 5) {
                ss << ",\"ecode\":" << (int)data_area[4];
            } else if (error_status == 0) {
                uint16_t block_count = safe_letohs(data_area + 2);
                ss << ",\"bc\":" << block_count;
                if (command_code == 0x0055 && data_area_len >= 6) { // Read Response Data
                    uint16_t data_size = safe_letohs(data_area + 4);
                    ss << ",\"len\":" << data_size;
                    if (data_area_len >= 6 + data_size) {
                         ss << ",\"data\":";
                         append_hex_data(ss, data_area + 6, data_size);
                    }
                }
            }
            break;
        }
    }
    ss << "}";
    return ss.str();
}

// --- (신규) CSV 출력을 위한 구조적 PDU 파서 ---
XgtFenParsedData XgtFenParser::parse_pdu_structured(const u_char* pdu, int pdu_len, bool is_response) {
    XgtFenParsedData data;
    if (pdu_len < 2) return data;

    uint16_t command_code = safe_letohs(pdu);
    data.cmd = std::to_string(command_code);
    
    uint16_t datatype_code = 0;
    if (pdu_len >= 4) {
        datatype_code = safe_letohs(pdu + 2);
        data.dt = std::to_string(datatype_code);
    }

    const u_char* data_area = pdu + 4;
    int data_area_len = pdu_len - 4;

    switch (command_code) {
        case 0x0054: // Read Request
        case 0x0058: // Write Request
        {
            if (data_area_len < 4) break;
            data.bc = std::to_string(safe_letohs(data_area + 2));
            const u_char* var_ptr = data_area + 4;
            int remaining_len = data_area_len - 4;

            if (datatype_code == 0x0014) { // Continuous Block
                if (remaining_len < 2) break;
                uint16_t var_len = safe_letohs(var_ptr);
                if (remaining_len >= 2 + var_len) {
                    data.var_nm = std::string(reinterpret_cast<const char*>(var_ptr + 2), var_len);
                    if(command_code == 0x0054) { // Read
                        if (remaining_len >= 4 + var_len) {
                           data.var_len = std::to_string(safe_letohs(var_ptr + 2 + var_len));
                        }
                    } else { // Write
                         if (remaining_len >= 4 + var_len) {
                            uint16_t data_size = safe_letohs(var_ptr + 2 + var_len);
                            data.var_len = std::to_string(data_size);
                            if (remaining_len >= 4 + var_len + data_size) {
                                std::stringstream ss_hex;
                                append_hex_data(ss_hex, var_ptr + 4 + var_len, data_size);
                                data.data_hex = ss_hex.str();
                            }
                        }
                    }
                }
            }
            break;
        }
        case 0x0055: // Read Response
        case 0x0059: // Write Response
        {
            if (data_area_len < 4) break;
            uint16_t error_status = safe_letohs(data_area);
            data.err = std::to_string(error_status);

            if (error_status == 0xFFFF && data_area_len >= 5) {
                data.ecode = std::to_string((int)data_area[4]);
            } else if (error_status == 0) {
                data.bc = std::to_string(safe_letohs(data_area + 2));
                if (command_code == 0x0055 && data_area_len >= 6) { // Read Response Data
                    uint16_t data_size = safe_letohs(data_area + 4);
                    data.var_len = std::to_string(data_size);
                    if (data_area_len >= 6 + data_size) {
                         std::stringstream ss_hex;
                         append_hex_data(ss_hex, data_area + 6, data_size);
                         data.data_hex = ss_hex.str();
                    }
                }
            }
            break;
        }
    }
    return data;
}


// --- IProtocolParser Interface Implementation ---

XgtFenParser::~XgtFenParser() {}

std::string XgtFenParser::getName() const { return "xgt_fen"; }

// --- 추가: XGT-FEnet용 CSV 헤더 ---
void XgtFenParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,";
    csv_stream << "ivid,pdu.cmd,pdu.dt,pdu.bc,pdu.err,pdu.ecode,";
    csv_stream << "pdu.var.nm,pdu.var.len,pdu.var.data\n";
}


bool XgtFenParser::isProtocol(const u_char* payload, int size) const {
    return size >= 20 && memcmp(payload, "LSIS-XGT", 8) == 0;
}

void XgtFenParser::parse(const PacketInfo& info) {
    const u_char* header = info.payload;
    if (info.payload_size < 20) return;

    uint8_t frame_source = header[13];
    uint16_t invoke_id = safe_letohs(header + 14);
    
    const u_char* pdu = header + 20;
    int pdu_len = info.payload_size - 20;

    std::string pdu_json;
    std::string direction; 
    XgtFenRequestInfo* req_info_ptr = nullptr;
    bool is_response = (frame_source == 0x11);
    
    if (is_response && m_pending_requests[info.flow_id].count(invoke_id)) {
        direction = "response";
        req_info_ptr = &m_pending_requests[info.flow_id][invoke_id];
    }
    else if (frame_source == 0x33) { // Request
        direction = "request";
        if (pdu_len >= 4) {
             XgtFenRequestInfo new_req;
             new_req.invoke_id = invoke_id;
             new_req.command = safe_letohs(pdu);
             new_req.data_type = safe_letohs(pdu + 2);
             m_pending_requests[info.flow_id][invoke_id] = new_req;
        }
    } else {
        return; // Unknown source or unmapped response
    }
    
    // --- 1. JSONL 파일 쓰기 (기존 'd' 구조 유지) ---
    pdu_json = parse_fenet_pdu_json(pdu, pdu_len, req_info_ptr);
    std::stringstream details_ss_json;
    details_ss_json << "{\"ivid\":" << invoke_id << ",\"pdu\":" << pdu_json << "}";
    writeJsonl(info, direction, details_ss_json.str());

    // --- 2. CSV 파일 쓰기 (정규화된(flattened) 컬럼) ---
    XgtFenParsedData csv_data = parse_pdu_structured(pdu, pdu_len, is_response);
    
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                      << direction << ","
                      << invoke_id << ","
                      << csv_data.cmd << "," << csv_data.dt << "," << csv_data.bc << ","
                      << csv_data.err << "," << csv_data.ecode << ","
                      << escape_csv(csv_data.var_nm) << "," << csv_data.var_len << ","
                      << escape_csv(csv_data.data_hex) << "\n";
    }

    if (req_info_ptr) {
        m_pending_requests[info.flow_id].erase(invoke_id);
    }
}
