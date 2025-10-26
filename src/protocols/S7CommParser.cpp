#include "S7CommParser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string> // for std::to_string
#include <algorithm> // for std::max

S7CommParser::~S7CommParser() {}

// --- Helper Functions ---
static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}
static uint32_t s7_addr_to_int(const u_char* ptr) {
    // S7 주소는 3바이트 Big Endian (예: 0x84 0x00 0x0A -> DB 0, Byte 1, Bit 2)
    return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
}

// --- (신규) CSV 출력을 위한 구조체 ---
struct S7ParamItem {
    std::string syn, tsz, amt, db, ar, addr;
};
struct S7DataItem {
    std::string rc, len;
};
struct S7ParsedData {
    std::string ros;
    std::string fn;
    std::string ic;
    std::vector<S7ParamItem> param_items;
    std::vector<S7DataItem> data_items;
};


// --- (신규) CSV 출력을 위한 구조적 PDU 파서 ---
S7ParsedData parse_s7_pdu_structured(const u_char* s7pdu, int s7pdu_len, const S7CommRequestInfo* req_info) {
    S7ParsedData data;
    if (s7pdu_len < 10) return data;

    uint8_t rosctr = s7pdu[1];
    data.ros = std::to_string(rosctr);
    uint16_t param_len = safe_ntohs(s7pdu + 6);
    uint16_t data_len = safe_ntohs(s7pdu + 8);
    int header_size = (rosctr == 0x01 || rosctr == 0x07) ? 10 : 12; // 0x07=Ack_Data

    if (param_len > 0 && (s7pdu_len >= header_size + param_len)) {
        const u_char* param = s7pdu + header_size;
        data.fn = std::to_string(param[0]);
        if ((param[0] == 0x04 || param[0] == 0x05) && param_len >= 2) { // Read/Write Var
            uint8_t item_count = param[1];
            data.ic = std::to_string(item_count);
            const u_char* item_ptr = param + 2;
            for(int i = 0; i < item_count; ++i) {
                if ((item_ptr + 12) > (param + param_len)) break;
                
                S7ParamItem item;
                item.syn = std::to_string(item_ptr[2]);
                item.tsz = std::to_string(item_ptr[3]); // Transport Size
                item.amt = std::to_string(safe_ntohs(item_ptr + 4)); // Amount
                item.ar = std::to_string(item_ptr[8]); // Area
                if (item_ptr[8] == 0x84) { // Area: Data blocks (DB)
                    item.db = std::to_string(safe_ntohs(item_ptr + 6));
                }
                // 주소: 3바이트 Big Endian, 마지막 3비트는 비트 주소이므로 시프트
                item.addr = std::to_string(s7_addr_to_int(item_ptr + 9) >> 3); 
                
                data.param_items.push_back(item);
                item_ptr += 12;
            }
        }
    }

    if (data_len > 0 && (s7pdu_len >= header_size + param_len + data_len)) {
        const u_char* data_ptr = s7pdu + header_size + param_len;
        
        // Read Response (rosctr=3)이고, 매칭되는 요청(req_info)이 있을 때
        if (rosctr == 3 && req_info && !req_info->items.empty()) {
            const u_char* data_item_ptr = data_ptr;
            for(size_t i = 0; i < req_info->items.size(); ++i) {
                if ((data_item_ptr + 1) > (data_ptr + data_len)) break; 
                
                S7DataItem item;
                item.rc = std::to_string(data_item_ptr[0]); // Return Code
                
                if (data_item_ptr[0] == 0xff) { // Data follows
                    if ((data_item_ptr + 4) > (data_ptr + data_len)) { // 헤더가 충분하지 않음
                         data_item_ptr++; // 다음 아이템으로 (에러지만)
                         continue;
                    }
                    uint16_t read_len_bits = safe_ntohs(data_item_ptr + 2);
                    uint16_t read_len_bytes = (read_len_bits + 7) / 8; // 비트를 바이트로 올림
                    item.len = std::to_string(read_len_bytes);
                    
                     if((data_item_ptr + 4 + read_len_bytes) <= (data_ptr + data_len)) {
                         data_item_ptr += 4 + read_len_bytes;
                         // S7은 홀수 바이트 데이터 뒤에 0x00 패딩을 추가함
                         if (read_len_bytes % 2 != 0) data_item_ptr++; 
                     } else { 
                         data_item_ptr += 4; // 데이터가 잘렸지만 다음 아이템으로
                     }
                } else { // No data (e.g., error code)
                    data_item_ptr++; 
                }
                data.data_items.push_back(item);
            }
        }
    }
    return data;
}


// --- (기존) JSONL 출력을 위한 PDU 파서 (이름 변경) ---
std::string parse_s7_pdu_json(const u_char* s7pdu, int s7pdu_len, const S7CommRequestInfo* req_info) {
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
                
                uint8_t area = item_ptr[8];
                ss << (i > 0 ? "," : "") << "{";
                ss << "\"syn\":" << (int)item_ptr[2];
                ss << ",\"tsz\":" << (int)item_ptr[3];
                ss << ",\"amt\":" << safe_ntohs(item_ptr + 4);
                if (area == 0x84) { // Area: Data blocks (DB)
                    ss << ",\"db\":" << safe_ntohs(item_ptr + 6);
                }
                ss << ",\"ar\":" << (int)area;
                ss << ",\"addr\":" << (s7_addr_to_int(item_ptr + 9) >> 3);
                ss << "}";

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

// --- 추가: S7Comm용 CSV 헤더 (정규화 + 확장) ---
void S7CommParser::writeCsvHeader(std::ofstream& csv_stream) {
    // Base columns
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,";
    // Normalized 'd' columns from python script
    csv_stream << "prid,pdu.ros,pdu.prm.fn,pdu.prm.ic,";
    // Exploded 'itms' columns
    csv_stream << "pdu.prm.itms.syn,pdu.prm.itms.tsz,pdu.prm.itms.amt,pdu.prm.itms.db,pdu.prm.itms.ar,pdu.prm.itms.addr,";
    // Exploded 'dat.itms' columns
    csv_stream << "pdu.dat.itms.rc,pdu.dat.itms.len\n";
}


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
    std::string direction; 
    S7CommRequestInfo* req_info_ptr = nullptr;

    if ((rosctr == 0x02 || rosctr == 0x03) && m_pending_requests[info.flow_id].count(pdu_ref)) {
        direction = "response";
        req_info_ptr = &m_pending_requests[info.flow_id][pdu_ref];
    }
    else if (rosctr == 0x01) { // Job
        direction = "request";
        S7CommRequestInfo new_req;
        new_req.timestamp = std::chrono::steady_clock::now();
        new_req.pdu_ref = pdu_ref;
        uint16_t param_len = safe_ntohs(s7_pdu + 6);
        if (param_len > 0 && (s7_pdu_len >= 10 + param_len)) {
            const u_char* param = s7_pdu + 10;
            new_req.function_code = param[0];
            if ((new_req.function_code == 0x04 || new_req.function_code == 0x05) && param_len >=2) { // Read/Write Var
                uint8_t item_count = param[1];
                new_req.items.resize(item_count); // 응답 파싱을 위해 아이템 개수만 저장
            }
        }
        m_pending_requests[info.flow_id][pdu_ref] = new_req;
        req_info_ptr = &m_pending_requests[info.flow_id][pdu_ref]; // 요청 정보도 파싱을 위해 전달
    } else {
        return; // Not a job or a mapped response
    }
    
    // --- 1. JSONL 파일 쓰기 (기존 'd' 구조 유지) ---
    pdu_json = parse_s7_pdu_json(s7_pdu, s7_pdu_len, (direction == "response") ? req_info_ptr : nullptr);
    std::stringstream details_ss_json;
    details_ss_json << "{\"prid\":" << pdu_ref << ",\"pdu\":" << pdu_json << "}";
    writeJsonl(info, direction, details_ss_json.str());

    // --- 2. CSV 파일 쓰기 (정규화 + 확장) ---
    S7ParsedData csv_data = parse_s7_pdu_structured(s7_pdu, s7_pdu_len, (direction == "response") ? req_info_ptr : nullptr);
    
    if (m_csv_stream && m_csv_stream->is_open()) {
        std::stringstream base_csv_line;
        base_csv_line << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                      << direction << ",";
        
        std::stringstream details_csv_line;
        details_csv_line << pdu_ref << ","
                         << csv_data.ros << "," << csv_data.fn << "," << csv_data.ic << ",";

        size_t max_items = std::max(csv_data.param_items.size(), csv_data.data_items.size());

        if (max_items == 0) {
            // Write one line with empty item details
            *m_csv_stream << base_csv_line.str() << details_csv_line.str()
                          << ",,,,,,,,\n"; // 8 empty fields for param_items + data_items
        } else {
            // Explode logic: write one line per item
            for (size_t i = 0; i < max_items; ++i) {
                *m_csv_stream << base_csv_line.str() << details_csv_line.str();
                
                if (i < csv_data.param_items.size()) {
                    const auto& item = csv_data.param_items[i];
                    *m_csv_stream << item.syn << "," << item.tsz << "," << item.amt << ","
                                  << item.db << "," << item.ar << "," << item.addr << ",";
                } else {
                    *m_csv_stream << ",,,,,,"; // 6 empty param item fields
                }

                if (i < csv_data.data_items.size()) {
                    const auto& item = csv_data.data_items[i];
                    *m_csv_stream << item.rc << "," << item.len << "\n";
                } else {
                    *m_csv_stream << ",,\n"; // 2 empty data item fields
                }
            }
        }
    }
    
    if (direction == "response") {
        m_pending_requests[info.flow_id].erase(pdu_ref);
    }
}
