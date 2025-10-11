#include "BaseProtocolParser.h"
#include <sstream>

// 추가: CSV 이스케이프 처리 구현
std::string BaseProtocolParser::escape_csv(const std::string& s) {
    std::string result = "\"";
    for (char c : s) {
        if (c == '"') {
            result += "\"\"";
        } else {
            result += c;
        }
    }
    result += "\"";
    return result;
}

void BaseProtocolParser::setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) {
    m_json_stream = json_stream;
    m_csv_stream = csv_stream;
}

void BaseProtocolParser::writeOutput(const PacketInfo& info, const std::string& details_json) {
    // 스트림이 유효하면 JSONL 파일에 기록
    if (m_json_stream && m_json_stream->is_open()) {
        *m_json_stream << "{\"@timestamp\":\"" << info.timestamp << "\","
                       << "\"sip\":\"" << info.src_ip << "\",\"sp\":" << info.src_port << ","
                       << "\"dip\":\"" << info.dst_ip << "\",\"dp\":" << info.dst_port << ","
                       << "\"sq\":" << info.tcp_seq << ",\"ak\":" << info.tcp_ack << ",\"fl\":" << (int)info.tcp_flags << ","
                       << "\"d\":" << details_json << "}\n";
    }

    // 스트림이 유효하면 CSV 파일에 기록
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                      << escape_csv(details_json) << "\n";
    }
}

