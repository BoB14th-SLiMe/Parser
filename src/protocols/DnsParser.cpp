#include "DnsParser.h"
#include <sstream>
#include <arpa/inet.h>
#include <string> // for std::to_string

DnsParser::~DnsParser() {}

std::string DnsParser::getName() const {
    return "dns";
}

// --- 추가: DNS용 CSV 헤더 ---
void DnsParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,tid,fl.dns,qc,ac\n";
}


bool DnsParser::isProtocol(const u_char* payload, int size) const {
    // DNS typically uses UDP port 53, minimum header size is 12 bytes.
    return size >= 12;
}

void DnsParser::parse(const PacketInfo& info) {
    std::stringstream details_ss_json;
    std::string direction = "unknown";
    
    // --- 파싱된 필드를 저장할 변수 ---
    std::string tid_str, flags_str, qdcount_str, ancount_str;
    std::string len_str = std::to_string(info.payload_size);


    if (info.payload_size >= 12) {
        uint16_t tid = ntohs(*(uint16_t*)(info.payload));
        uint16_t flags = ntohs(*(uint16_t*)(info.payload + 2));
        uint16_t qdcount = ntohs(*(uint16_t*)(info.payload + 4)); // Question count
        uint16_t ancount = ntohs(*(uint16_t*)(info.payload + 6)); // Answer count
        
        direction = (flags & 0x8000) ? "response" : "request";

        // JSONL용 문자열 생성
        details_ss_json << "{\"tid\":" << tid << ",\"fl\":" << flags
                   << ",\"qc\":" << qdcount << ",\"ac\":" << ancount << "}";
        
        // CSV용 변수 저장
        tid_str = std::to_string(tid);
        flags_str = std::to_string(flags);
        qdcount_str = std::to_string(qdcount);
        ancount_str = std::to_string(ancount);

    } else {
        details_ss_json << "{\"len\":" << info.payload_size << "}";
    }

    // --- 1. JSONL 파일 쓰기 (기존 'd' 구조 유지) ---
    writeJsonl(info, direction, details_ss_json.str());

    // --- 2. CSV 파일 쓰기 (정규화된(flattened) 컬럼) ---
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                      << direction << ",";
        
        if (info.payload_size >= 12) {
             *m_csv_stream << tid_str << "," << flags_str << "," << qdcount_str << "," << ancount_str << "\n";
        } else {
             // len만 있는 경우
             *m_csv_stream << ",,,\n"; // tid, fl.dns, qc, ac 컬럼 비워둠
        }
    }
}
