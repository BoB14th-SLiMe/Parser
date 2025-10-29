#include "TcpSessionParser.h"
#include "../network/network_headers.h"
#include <nlohmann/json.hpp>
#include <sstream>

TcpSessionParser::TcpSessionParser() {}
TcpSessionParser::~TcpSessionParser() {}

std::string TcpSessionParser::getName() const {
    return "tcp_session";
}

// 이 파서는 모든 TCP 패킷에 대해 실행되어야 하므로, isProtocol은 항상 true를 반환합니다.
bool TcpSessionParser::isProtocol(const PacketInfo& /*info*/) const {
    return true;
}

void TcpSessionParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir\n";
}

void TcpSessionParser::parse(const PacketInfo& info) {
    // TCP 세션의 방향 결정
    std::string direction = "unknown";
    
    // SYN 플래그로 방향 판단
    if (info.tcp_flags & TH_SYN) {
        if (info.tcp_flags & TH_ACK) {
            direction = "syn_ack"; // SYN-ACK (서버 -> 클라이언트)
        } else {
            direction = "syn"; // SYN (클라이언트 -> 서버)
        }
    } else if (info.tcp_flags & TH_FIN) {
        direction = "fin";
    } else if (info.tcp_flags & TH_RST) {
        direction = "rst";
    } else if (info.tcp_flags & TH_ACK) {
        direction = "ack";
    }
    
    // JSON details 생성
    nlohmann::json details;
    details["seq"] = info.tcp_seq;
    details["ack"] = info.tcp_ack;
    details["flags"]["syn"] = (info.tcp_flags & TH_SYN) ? 1 : 0;
    details["flags"]["ack"] = (info.tcp_flags & TH_ACK) ? 1 : 0;
    details["flags"]["fin"] = (info.tcp_flags & TH_FIN) ? 1 : 0;
    details["flags"]["rst"] = (info.tcp_flags & TH_RST) ? 1 : 0;
    details["flags"]["psh"] = (info.tcp_flags & TH_PUSH) ? 1 : 0;
    details["flags"]["urg"] = (info.tcp_flags & TH_URG) ? 1 : 0;
    
    // writeJsonl을 사용하여 JSONL, Redis, Elasticsearch에 자동 전송
    writeJsonl(info, direction, details.dump());

    // CSV는 별도로 작성 (간단한 정보만)
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
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
    }
}