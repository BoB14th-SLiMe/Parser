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

// Optimized PDU parser with full feature support
std::string parse_fenet_pdu(const u_char* pdu, int pdu_len, const XgtFenRequestInfo* req_info) {
    if (pdu_len < 2) return "{}";
    std::stringstream ss;
    ss << "{";

    uint16_t command_code = safe_letohs(pdu);
    uint16_t datatype_code = (pdu_len >= 4) ? safe_letohs(pdu + 2) : 0;

    // --- 수정: 머신러닝 처리를 위해 숫자 값으로 직접 출력 ---
    ss << "\"cmd\":" << command_code;
    if (pdu_len >= 4) {
        ss << ",\"dt\":" << datatype_code;
    }

    const u_char* data_area = pdu + 4;
    int data_area_len = pdu_len - 4;

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


// --- IProtocolParser Interface Implementation ---

XgtFenParser::~XgtFenParser() {}

std::string XgtFenParser::getName() const { return "xgt_fen"; }

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
    XgtFenRequestInfo req_info;
    bool is_response = (frame_source == 0x11);
    
    if (is_response && m_pending_requests[info.flow_id].count(invoke_id)) {
        req_info = m_pending_requests[info.flow_id][invoke_id];
        pdu_json = parse_fenet_pdu(pdu, pdu_len, &req_info);
        m_pending_requests[info.flow_id].erase(invoke_id);
    }
    else if (frame_source == 0x33) { // Request
        pdu_json = parse_fenet_pdu(pdu, pdu_len, nullptr);
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
    
    std::stringstream details_ss;
    details_ss << "{\"ivid\":" << invoke_id << ",\"pdu\":" << pdu_json << "}";
    
    writeOutput(info, details_ss.str());
}

