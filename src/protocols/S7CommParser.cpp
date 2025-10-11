#include "S7CommParser.h"
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
static uint32_t s7_addr_to_int(const u_char* ptr) {
    return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
}

// Optimized PDU Parser
std::string parse_s7_pdu_optimized(const u_char* s7pdu, int s7pdu_len, const S7CommRequestInfo* req_info) {
    if (s7pdu_len < 10) return "{}";
    std::stringstream ss;
    ss << "{";
    uint8_t rosctr = s7pdu[1];
    uint16_t param_len = safe_ntohs(s7pdu + 6);
    uint16_t data_len = safe_ntohs(s7pdu + 8);
    int header_size = (rosctr == 0x01 || rosctr == 0x07) ? 10 : 12;

    ss << "\"ros\":" << (int)rosctr;

    if (param_len > 0 && (s7pdu_len >= header_size + param_len)) {
        const u_char* param = s7pdu + header_size;
        ss << ",\"prm\":{\"fn\":" << (int)param[0];
        if ((param[0] == 0x04 || param[0] == 0x05) && param_len >= 2) {
            uint8_t item_count = param[1];
            ss << ",\"ic\":" << (int)item_count << ",\"itms\":[";
            const u_char* item_ptr = param + 2;
            for(int i = 0; i < item_count; ++i) {
                if ((item_ptr + 12) > (param + param_len)) break;
                ss << (i > 0 ? "," : "") << "{";
                ss << "\"ar\":" << (int)item_ptr[8];
                if (item_ptr[8] == 0x84) ss << ",\"db\":" << safe_ntohs(item_ptr + 6);
                ss << ",\"addr\":" << (s7_addr_to_int(item_ptr + 9) >> 3);
                ss << ",\"amt\":" << safe_ntohs(item_ptr + 4) << "}";
                item_ptr += 12;
            }
            ss << "]";
        }
        ss << "}";
    }

    if (data_len > 0 && (s7pdu_len >= header_size + param_len + data_len)) {
        const u_char* data = s7pdu + header_size + param_len;
        ss << ",\"dat\":{";
        if (rosctr == 3 && req_info && !req_info->items.empty()) {
            ss << "\"itms\":[";
            const u_char* data_item_ptr = data;
            for(size_t i = 0; i < req_info->items.size(); ++i) {
                if ((data_item_ptr + 1) > (data + data_len)) break;
                ss << (i > 0 ? "," : "") << "{\"rc\":" << (int)data_item_ptr[0];
                if (data_item_ptr[0] == 0xff) {
                    if ((data_item_ptr + 4) > (data + data_len)) {
                         ss << "}";
                         data_item_ptr++;
                         continue;
                    }
                    uint16_t read_len_bits = safe_ntohs(data_item_ptr + 2);
                    uint16_t read_len_bytes = (read_len_bits + 7) / 8;
                    ss << ",\"len\":" << read_len_bytes;
                     if((data_item_ptr + 4 + read_len_bytes) <= (data + data_len)) {
                         data_item_ptr += 4 + read_len_bytes;
                         if (read_len_bytes % 2 != 0) data_item_ptr++;
                     } else { data_item_ptr +=4; }
                } else { data_item_ptr++; }
                ss << "}";
            }
             ss << "]";
        }
        ss << "}";
    }
    ss << "}";
    return ss.str();
}

// --- IProtocolParser Interface Implementation ---
std::string S7CommParser::getName() const { return "s7comm"; }

bool S7CommParser::isProtocol(const u_char* payload, int size) const {
    return size >= 17 && payload[0] == 0x03 && payload[5] == 0xf0 && payload[7] == 0x32;
}

void S7CommParser::parse(const PacketInfo& info) {
    const u_char* s7_pdu = info.payload + 7;
    int s7_pdu_len = info.payload_size - 7;
    if (s7_pdu_len < 10) return;

    uint16_t pdu_ref = safe_ntohs(s7_pdu + 4);
    uint8_t rosctr = s7_pdu[1];

    std::string pdu_json;

    if ((rosctr == 0x02 || rosctr == 0x03) && m_pending_requests[info.flow_id].count(pdu_ref)) {
        S7CommRequestInfo req_info = m_pending_requests[info.flow_id][pdu_ref];
        pdu_json = parse_s7_pdu_optimized(s7_pdu, s7_pdu_len, &req_info);
        m_pending_requests[info.flow_id].erase(pdu_ref);
    }
    else if (rosctr == 0x01) { // Job
        S7CommRequestInfo new_req;
        new_req.timestamp = std::chrono::steady_clock::now();
        new_req.pdu_ref = pdu_ref;
        uint16_t param_len = safe_ntohs(s7_pdu + 6);
        if (param_len > 0 && (s7_pdu_len >= 10 + param_len)) {
            const u_char* param = s7_pdu + 10;
            new_req.function_code = param[0];
            if ((new_req.function_code == 0x04 || new_req.function_code == 0x05) && param_len >=2) { // Read/Write Var
                uint8_t item_count = param[1];
                const u_char* item_ptr = param + 2;
                for(int i=0; i < item_count; ++i) {
                     if ((item_ptr + 12) > (param + param_len)) break;
                     S7CommItem item;
                     new_req.items.push_back(item);
                     item_ptr += 12;
                }
            }
        }
        pdu_json = parse_s7_pdu_optimized(s7_pdu, s7_pdu_len, nullptr);
        m_pending_requests[info.flow_id][pdu_ref] = new_req;
    } else {
        return;
    }
    
    std::stringstream details_ss;
    details_ss << "{\"prid\":" << pdu_ref << ",\"pdu\":" << pdu_json << "}";
    
    // Corrected function call
    writeOutput(info, details_ss.str());
}

