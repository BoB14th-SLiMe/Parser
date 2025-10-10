#include "XgtFenParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>

XgtFenParser::~XgtFenParser() {} // 소멸자 정의 추가

// --- Helper Functions ---
static uint16_t safe_letohs(const u_char* ptr) {
    return (uint16_t)(ptr[0] | (ptr[1] << 8));
}

// Optimized PDU parser
std::string parse_pdu_optimized(const u_char* pdu, int pdu_len, bool is_request) {
    if (pdu_len < 2) return "{}";
    std::stringstream ss;
    ss << "{";

    uint16_t command = safe_letohs(pdu);
    ss << "\"cmd\":" << command;

    if (pdu_len < 4) { ss << "}"; return ss.str(); }
    uint16_t data_type = safe_letohs(pdu + 2);
    ss << ",\"dt\":" << data_type;

    const u_char* data = pdu + 4;
    int data_len = pdu_len - 4;

    switch (command) {
        case 0x0054: // Read Request
        case 0x0058: // Write Request
        {
            if (data_len < 4) break;
            uint16_t block_count = safe_letohs(data + 2);
            ss << ",\"bc\":" << block_count;

            if (data_type == 0x0014) { // Continuous
                if (data_len < 6) break;
                const u_char* var_ptr = data + 4;
                uint16_t var_len = safe_letohs(var_ptr);
                if (var_len > 0 && data_len >= 6 + var_len) {
                    ss << ",\"var\":{\"nm\":\"" << std::string(reinterpret_cast<const char*>(var_ptr + 2), var_len) << "\"";
                    if(command == 0x0054){ // Read
                        ss << ",\"len\":" << safe_letohs(var_ptr + 2 + var_len) << "}";
                    } else { // Write
                        uint16_t write_size = safe_letohs(var_ptr + 2 + var_len);
                        ss << ",\"len\":" << write_size << "}";
                    }
                }
            } else { // Individual
                ss << ",\"vars\":[";
                const u_char* var_ptr = data + 4;
                for (uint16_t i = 0; i < block_count; ++i) {
                    if ((var_ptr + 2) > (pdu + pdu_len)) break;
                    uint16_t var_len = safe_letohs(var_ptr);
                    if ((var_ptr + 2 + var_len) > (pdu + pdu_len)) break;
                    ss << (i > 0 ? "," : "") << "{\"nm\":\"" << std::string(reinterpret_cast<const char*>(var_ptr + 2), var_len) << "\"}";
                    var_ptr += (2 + var_len);
                }
                ss << "]";
            }
            break;
        }
        case 0x0055: // Read Response
        case 0x0059: // Write Response
        {
            if (data_len < 4) break;
            uint16_t error_status = safe_letohs(data);
            ss << ",\"err\":" << error_status;
            if(error_status != 0) {
                 ss << ",\"ecode\":" << (int)data[3];
                 break;
            }
            uint16_t block_count = safe_letohs(data + 2);
            ss << ",\"bc\":" << block_count;
            if (command == 0x0055 && data_type == 0x0014) { // Continuous Read Response
                if (data_len >= 6) ss << ",\"len\":" << safe_letohs(data + 4);
            }
            break;
        }
    }
    ss << "}";
    return ss.str();
}

// --- IProtocolParser Interface Implementation ---

std::string XgtFenParser::getName() const { return "xgt_fen"; }
void XgtFenParser::setOutputStream(std::ofstream* stream) { m_output_stream = stream; }

bool XgtFenParser::isProtocol(const u_char* payload, int size) const {
    return size >= 22 && memcmp(payload, "LSIS-XGT", 8) == 0;
}

void XgtFenParser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;
    const u_char* header = info.payload;
    if (info.payload_size < 20) return;

    uint8_t frame_source = header[13];
    uint16_t invoke_id = safe_letohs(header + 14);
    
    const u_char* pdu = header + 20;
    int pdu_len = info.payload_size - 20;

    std::string details_json;

    if (frame_source == 0x11 && m_pending_requests[info.flow_id].count(invoke_id)) {
        details_json = parse_pdu_optimized(pdu, pdu_len, false);
        m_pending_requests[info.flow_id].erase(invoke_id);
    }
    else if (frame_source == 0x33) {
        details_json = parse_pdu_optimized(pdu, pdu_len, true);
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
    
    *m_output_stream << "{\"@timestamp\":\"" << info.timestamp << "\","
                   << "\"sip\":\"" << info.src_ip << "\",\"sp\":" << info.src_port << ","
                   << "\"dip\":\"" << info.dst_ip << "\",\"dp\":" << info.dst_port << ","
                   << "\"sq\":" << info.tcp_seq << ",\"ak\":" << info.tcp_ack << ",\"fl\":" << (int)info.tcp_flags << ","
                   << "\"ivid\":" << invoke_id << ",\"d\":" << details_json << "}\n";
}

