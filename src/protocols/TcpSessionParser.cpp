#include "TcpSessionParser.h"
#include "../network/network_headers.h"
#include "../network/network_headers.h"
#include "../include/nlohmann/json.hpp"
#include <sstream>

TcpSessionParser::TcpSessionParser() {}
TcpSessionParser::~TcpSessionParser() {}

std::string TcpSessionParser::getName() const {
    return "tcp_session";
}

// 이 파서는 모든 TCP 패킷에 대해 실행되어야 하므로, isProtocol은 항상 true를 반환합니다.
bool TcpSessionParser::isProtocol(const PacketInfo& info) const {
    return true;
}

void TcpSessionParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir\n";
}

void TcpSessionParser::parse(const PacketInfo& info) {
    // JSONL 쓰기
    if (m_json_stream && m_json_stream->is_open()) {
        nlohmann::json details;
        details["seq"] = info.tcp_seq;
        details["ack"] = info.tcp_ack;
        details["flags"]["syn"] = (info.tcp_flags & TH_SYN) ? 1 : 0;
        details["flags"]["ack"] = (info.tcp_flags & TH_ACK) ? 1 : 0;
        details["flags"]["fin"] = (info.tcp_flags & TH_FIN) ? 1 : 0;
        details["flags"]["rst"] = (info.tcp_flags & TH_RST) ? 1 : 0;
        
        nlohmann::json root;
        root["@timestamp"] = info.timestamp;
        root["flow_id"] = info.flow_id;
        root["sip"] = info.src_ip;
        root["dip"] = info.dst_ip;
        root["sp"] = info.src_port;
        root["dp"] = info.dst_port;
        root["d"] = details;
        *m_json_stream << root.dump() << std::endl;
    }

    // CSV 쓰기
    if (m_csv_stream && m_csv_stream->is_open()) {
        std::string direction = "unknown"; // TCP 세션의 방향은 플래그나 페이로드에 따라 더 복잡하게 결정될 수 있으나, 여기서는 간단히 "unknown"으로 설정
        
        std::stringstream csv_line;
        csv_line << info.timestamp << ","
                 << info.src_mac << ","
                 << info.dst_mac << ","
                 << info.src_ip << ","
                 << info.src_port << ","
                 << info.dst_ip << ","
                 << info.dst_port << ","
                 << info.tcp_seq << ","
                 << info.tcp_ack << ","
                 << (int)info.tcp_flags << ","
                 << direction << "\n";
        *m_csv_stream << csv_line.str();
    }
}