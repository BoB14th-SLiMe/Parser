#include "DnsParser.h"
#include <sstream>
#include <arpa/inet.h>
#include <string> // for std::to_string
#include <iostream> // For std::cout (debugging)

DnsParser::~DnsParser() {}

std::string DnsParser::getName() const {
    return "dns";
}

// --- 추가: DNS용 CSV 헤더 ---
void DnsParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,tid,fl.dns,qc,ac\n";
}


bool DnsParser::isProtocol(const PacketInfo& info) const {
    return info.protocol == IPPROTO_UDP &&
           (info.dst_port == 53 || info.src_port == 53) &&
           info.payload_size >= 12;
}

void DnsParser::parse(const PacketInfo& info) {
    std::stringstream details_ss_json;
    std::string direction = "unknown";
    
    std::string tid_str, flags_str, qdcount_str, ancount_str;
    std::string len_str = std::to_string(info.payload_size);

    if (info.payload_size >= 12) {
        uint16_t tid = ntohs(*(uint16_t*)(info.payload));
        uint16_t flags = ntohs(*(uint16_t*)(info.payload + 2));
        uint16_t qdcount = ntohs(*(uint16_t*)(info.payload + 4));
        uint16_t ancount = ntohs(*(uint16_t*)(info.payload + 6));
        
        direction = (flags & 0x8000) ? "response" : "request";

        details_ss_json << "{\"tid\":" << tid << ",\"fl\":" << flags
                   << ",\"qc\":" << qdcount << ",\"ac\":" << ancount << "}";
        
        tid_str = std::to_string(tid);
        flags_str = std::to_string(flags);
        qdcount_str = std::to_string(qdcount);
        ancount_str = std::to_string(ancount);
    } else {
        details_ss_json << "{\"len\":" << info.payload_size << "}";
    }

    writeJsonl(info, direction, details_ss_json.str());

    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << ","           // 추가!
                      << info.tcp_ack << ","           // 추가!
                      << (int)info.tcp_flags << ","    // 추가!
                      << direction << ",";
        
        if (info.payload_size >= 12) {
             *m_csv_stream << tid_str << "," << flags_str << "," 
                           << qdcount_str << "," << ancount_str << "\n";
        } else {
             *m_csv_stream << ",,,\n";
        }
    }
}
