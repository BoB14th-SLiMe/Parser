#include "UnknownParser.h"
#include <sstream>
#include <string> // for std::to_string

UnknownParser::~UnknownParser() {}

std::string UnknownParser::getName() const {
    return "unknown";
}

// --- 추가: Unknown 파서용 CSV 헤더 (Generic과 동일) ---
void UnknownParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,len\n";
}


bool UnknownParser::isProtocol(const PacketInfo& info) const {
    // This parser should be called last and handles any packet.
    return true;
}

void UnknownParser::parse(const PacketInfo& info) {
    std::stringstream details_ss_json;
    details_ss_json << "{\"len\":" << info.payload_size << "}";
    std::string direction = "unknown";

    writeJsonl(info, direction, details_ss_json.str());

    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << ","           // 추가!
                      << info.tcp_ack << ","           // 추가!
                      << (int)info.tcp_flags << ","    // 추가!
                      << direction << ","
                      << info.payload_size << "\n";
    }
}
