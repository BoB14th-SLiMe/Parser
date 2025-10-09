#include "S7CommParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

// --- Helper Functions ---
// These functions are specific to S7comm parsing and are kept here.
static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

static uint32_t s7_addr_to_int(const u_char* ptr) {
    // S7 address is 3 bytes, big-endian
    return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
}

static std::string get_s7comm_rosctr_name(uint8_t r) {
    switch(r) {
        case 0x01: return "Job";
        case 0x02: return "Ack";
        case 0x03: return "Ack_Data";
        case 0x07: return "Userdata";
        default: return "Unknown";
    }
}

static std::string get_s7comm_param_function_name(uint8_t f) {
     switch(f) {
        case 0x00: return "CPU services";
        case 0xF0: return "Setup communication";
        case 0x04: return "Read Var";
        case 0x05: return "Write Var";
        default: return "Unknown";
    }
}

static std::string get_s7comm_area_name(uint8_t a) {
    switch(a) {
        case 0x81: return "Inputs";
        case 0x82: return "Outputs";
        case 0x83: return "Flags";
        case 0x84: return "Data blocks";
        case 0x1c: return "S7 timers";
        case 0x1d: return "S7 counters";
        default: return "Unknown";
    }
}


// --- IProtocolParser Interface Implementation ---

std::string S7CommParser::getName() const {
    return "s7comm";
}

void S7CommParser::setOutputStream(std::ofstream* stream) {
    m_output_stream = stream;
}

bool S7CommParser::isProtocol(const u_char* payload, int size) const {
    // TPKT (4) + COTP (3) + S7 Header (10) = min 17 bytes for job
    if (size < 17) return false;
    // Check for TPKT version 3, COTP DT Data, S7 Protocol ID
    return payload[0] == 0x03 && payload[5] == 0xf0 && payload[7] == 0x32;
}

void S7CommParser::parse(const PacketInfo& info) {
    if (!m_output_stream || !m_output_stream->is_open()) return;

    const u_char* s7_pdu = info.payload + 7; // Skip TPKT+COTP headers
    int s7_pdu_len = info.payload_size - 7;
    if (s7_pdu_len < 10) return;

    uint16_t pdu_ref = safe_ntohs(s7_pdu + 4);
    uint8_t rosctr = s7_pdu[1];

    // --- S7comm Response Processing ---
    if ((rosctr == 0x02 || rosctr == 0x03) && m_pending_requests[info.flow_id].count(pdu_ref)) {
        S7CommRequestInfo req_info = m_pending_requests[info.flow_id][pdu_ref];
        std::string details_json = parse_pdu(s7_pdu, s7_pdu_len, false, &req_info);
        
        *m_output_stream << "{\"timestamp\":\"" << info.timestamp << "\",\"type\":\"" << get_s7comm_rosctr_name(rosctr) << "\","
                       << "\"src_ip\":\"" << info.src_ip << "\",\"src_port\":" << info.src_port << ","
                       << "\"dst_ip\":\"" << info.dst_ip << "\",\"dst_port\":" << info.dst_port << ","
                       << "\"pdu_ref\":" << pdu_ref << ","
                       << "\"details\":" << details_json << "}\n";
        
        m_pending_requests[info.flow_id].erase(pdu_ref);
    }
    // --- S7comm Request Processing ---
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
                     if ((item_ptr + 12) > (param + param_len)) break; // Bounds check
                     S7CommItem item;
                     item.length = safe_ntohs(item_ptr+4);
                     item.db_number = safe_ntohs(item_ptr+6);
                     item.area = item_ptr[8];
                     item.address = s7_addr_to_int(item_ptr+9);
                     new_req.items.push_back(item);
                     item_ptr += 12;
                }
            }
        }
        
        std::string details_json = parse_pdu(s7_pdu, s7_pdu_len, true, nullptr);
        m_pending_requests[info.flow_id][pdu_ref] = new_req;
        
        *m_output_stream << "{\"timestamp\":\"" << info.timestamp << "\",\"type\":\"Job\","
                       << "\"src_ip\":\"" << info.src_ip << "\",\"src_port\":" << info.src_port << ","
                       << "\"dst_ip\":\"" << info.dst_ip << "\",\"dst_port\":" << info.dst_port << ","
                       << "\"pdu_ref\":" << pdu_ref << ","
                       << "\"details\":" << details_json << "}\n";
    }
}

std::string S7CommParser::parse_pdu(const u_char* s7pdu, int s7pdu_len, bool is_request, const S7CommRequestInfo* req_info) {
    if (s7pdu_len < 10) return "{}";

    std::stringstream ss;
    ss << "{";

    uint8_t rosctr = s7pdu[1];
    uint16_t param_len = safe_ntohs(s7pdu + 6);
    uint16_t data_len = safe_ntohs(s7pdu + 8);
    
    // Header size varies based on ROSCTR type
    int header_size = (rosctr == 0x01 || rosctr == 0x07) ? 10 : 12;
    if (s7pdu_len < header_size) return "{}";
    
    const u_char* param = s7pdu + header_size;
    const u_char* data = param + param_len;

    ss << "\"rosctr\":\"" << get_s7comm_rosctr_name(rosctr) << "\"";
    
    if(param_len > 0 && (s7pdu_len >= header_size + param_len)) {
        ss << ",\"parameter\":{";
        uint8_t func = param[0];
        ss << "\"function\":\"" << get_s7comm_param_function_name(func) << "\"";
        if (func == 0x04 || func == 0x05) { // Read/Write Var
            if (param_len >= 2) {
                uint8_t item_count = param[1];
                ss << ",\"item_count\":" << (int)item_count;
                if (item_count > 0) {
                    ss << ",\"items\":[";
                    const u_char* item_ptr = param + 2;
                    for(int i = 0; i < item_count; ++i) {
                        if ((item_ptr + 12) > (param + param_len)) break; // Bounds check
                        
                        ss << (i > 0 ? "," : "") << "{";
                        ss << "\"area\":\"" << get_s7comm_area_name(item_ptr[8]) << "\"";
                        if (item_ptr[8] == 0x84) ss << ",\"db_number\":" << safe_ntohs(item_ptr + 6);
                        
                        uint32_t addr = s7_addr_to_int(item_ptr + 9);
                        ss << ",\"start_address\":" << (addr >> 3); // Address is in bits, convert to byte
                        ss << ",\"amount\":" << safe_ntohs(item_ptr + 4);
                        ss << "}";
                        
                        item_ptr += 12; // Move to next item
                    }
                    ss << "]";
                }
            }
        }
        ss << "}";
    }

    if(data_len > 0 && (s7pdu_len >= header_size + param_len + data_len)) {
        ss << ",\"data\":{";
        if (rosctr == 3 && req_info) { // Ack_Data, typically for Read Var Response
            const u_char* data_item_ptr = data;
            if (req_info->items.empty() && data_len > 0){
                 // Data exists but no request info, just dump hex
                 ss << "\"value\":\"";
                 std::stringstream hex_ss;
                 hex_ss << std::hex << std::setfill('0');
                 for (int j = 0; j < data_len; ++j) {
                     hex_ss << std::setw(2) << static_cast<int>(data_item_ptr[j]);
                 }
                 ss << hex_ss.str() << "\"";
            } else {
                 ss << "\"items\":[";
                 for(size_t i = 0; i < req_info->items.size(); ++i) {
                    if ((data_item_ptr + 4) > (data + data_len)) break; // Bounds check for header
                    
                    ss << (i > 0 ? "," : "") << "{";
                    uint8_t return_code = data_item_ptr[0];
                    ss << "\"return_code\":" << (int)return_code;

                    if (return_code == 0xff) { // Success
                        uint16_t read_len_bits = safe_ntohs(data_item_ptr + 2);
                        uint16_t read_len_bytes = (read_len_bits + 7) / 8;

                        ss << ",\"read_length_bytes\":" << read_len_bytes;

                        if((data_item_ptr + 4 + read_len_bytes) <= (data + data_len)) {
                           ss << ",\"value\":\"";
                           std::stringstream hex_ss;
                           hex_ss << std::hex << std::setfill('0');
                           for (int j = 0; j < read_len_bytes; ++j) {
                               hex_ss << std::setw(2) << static_cast<int>(data_item_ptr[4+j]);
                           }
                           ss << hex_ss.str() << "\"";
                           data_item_ptr += 4 + read_len_bytes;
                           if (read_len_bytes % 2 != 0) data_item_ptr++; // align to 2 bytes
                        } else {
                           data_item_ptr += 4;
                        }
                    } else {
                         data_item_ptr += 1;
                    }
                    ss << "}";
                 }
                 ss << "]";
            }
        }
        ss << "}";
    }

    ss << "}";
    return ss.str();
}

