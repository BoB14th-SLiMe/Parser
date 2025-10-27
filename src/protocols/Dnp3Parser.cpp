#include "Dnp3Parser.h"
#include <sstream>
#include <string> // for std::to_string

Dnp3Parser::~Dnp3Parser() {}

std::string Dnp3Parser::getName() const {
    return "dnp3";
}

// --- 추가: DNP3용 CSV 헤더 ---
void Dnp3Parser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,len,ctrl,dest,src\n";
}


bool Dnp3Parser::isProtocol(const PacketInfo& info) const {
    // DNP3는 TCP 또는 UDP 프로토콜을 사용하고 포트 20000을 사용합니다.
    // 또한, DNP3 Link Layer Start Bytes: 0x05 0x64로 시작합니다.
    return (info.protocol == IPPROTO_TCP || info.protocol == IPPROTO_UDP) &&
           (info.dst_port == 20000 || info.src_port == 20000) &&
           info.payload_size >= 2 &&
           info.payload[0] == 0x05 &&
           info.payload[1] == 0x64;
}

void Dnp3Parser::parse(const PacketInfo& info) {
    std::stringstream details_ss_json;
    std::string direction = "unknown";
    
    std::string len_str, ctrl_str, dest_str, src_str;
    std::string payload_len_str = std::to_string(info.payload_size);

    if (info.payload_size >= 10) {
        uint8_t len = info.payload[2];
        uint8_t ctrl = info.payload[3];
        uint16_t dest = *(uint16_t*)(info.payload + 4);
        uint16_t src = *(uint16_t*)(info.payload + 6);
        
        direction = (ctrl & 0x80) ? "request" : "response";

        details_ss_json << "{\"len\":" << (int)len << ",\"ctrl\":" << (int)ctrl 
                   << ",\"dest\":" << dest << ",\"src\":" << src << "}";
        
        len_str = std::to_string(len);
        ctrl_str = std::to_string(ctrl);
        dest_str = std::to_string(dest);
        src_str = std::to_string(src);
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
        
        if (info.payload_size >= 10) {
            *m_csv_stream << len_str << "," << ctrl_str << "," 
                          << dest_str << "," << src_str << "\n";
        } else {
            *m_csv_stream << payload_len_str << ",,,\n";
        }
    }
}
