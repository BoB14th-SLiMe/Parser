#include "BaseProtocolParser.h"
#include <sstream>

#include "BaseProtocolParser.h"
#include <iomanip> // for std::setw, std::setfill
#include <sstream> // for std::stringstream

// --- 추가: mac_to_string 정적 멤버 함수 구현 ---
std::string BaseProtocolParser::mac_to_string(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac[i]) << (i < 5 ? ":" : "");
    }
    return ss.str();
}

BaseProtocolParser::~BaseProtocolParser() {}

// CSV 이스케이프 처리 구현
std::string BaseProtocolParser::escape_csv(const std::string& s) {
    // 이미 ""로 감싸진 JSON 문자열일 수 있으므로,
    // 쉼표, 큰따옴표, 개행 문자가 포함된 경우에만 감싼다.
    if (s.find_first_of(",\"\n") == std::string::npos) {
        return s; // 이스케이프가 필요 없는 경우
    }
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

// --- 수정: setOutputStream이 CSV 파일 크기를 확인하고 헤더 작성 ---
void BaseProtocolParser::setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) {
    m_json_stream = json_stream;
    m_csv_stream = csv_stream;

    if (m_csv_stream && m_csv_stream->is_open()) {
        m_csv_stream->seekp(0, std::ios::end);
        if (m_csv_stream->tellp() == 0) {
            // --- 수정: 가상 함수 writeCsvHeader 호출 ---
            writeCsvHeader(*m_csv_stream);
        }
    }
}

// --- 수정: 기본 CSV 헤더 구현 (Generic/Unknown 파서용) ---
void BaseProtocolParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,d\n";
}


// --- 추가: JSONL 작성 헬퍼 ---
void BaseProtocolParser::writeJsonl(const PacketInfo& info, const std::string& direction, const std::string& details_json_content) {
    if (m_json_stream && m_json_stream->is_open()) {
        *m_json_stream << R"({"@timestamp":")" << info.timestamp << R"(",)"
                       << R"("flow_id":")" << info.flow_id << R"(",)"
                       << R"("sip":")" << info.src_ip << R"(",)"
                       << R"("dip":")" << info.dst_ip << R"(",)"
                       << R"("sp":)" << info.src_port << R"(,)"
                       << R"("dp":)" << info.dst_port << R"(,)"
                       << R"("sq":)" << info.tcp_seq << R"(,)"
                       << R"("ak":)" << info.tcp_ack << R"(,)"
                       << R"("fl":)" << (int)info.tcp_flags << R"(,)"
                       << R"("dir":")" << direction << R"(",)"
                       << R"("d":)" << details_json_content << R"(})" << std::endl;
    }
}

// --- 추가: 기본 CSV 라인 작성 헬퍼 (Generic/Unknown 파서용) ---
void BaseProtocolParser::writeBaseCsvLine(const PacketInfo& info, const std::string& direction, const std::string& details_json_content) {
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
                      << direction << ","
                      << escape_csv(details_json_content) << "\n";
    }
}
