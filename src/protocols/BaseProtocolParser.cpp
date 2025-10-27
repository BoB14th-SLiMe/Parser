#include "BaseProtocolParser.h"
#include "../TimeBasedCsvWriter.h"
#include <sstream>
#include <iomanip>
#include <iostream>

std::string BaseProtocolParser::mac_to_string(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac[i]) << (i < 5 ? ":" : "");
    }
    return ss.str();
}

BaseProtocolParser::~BaseProtocolParser() {}

std::string BaseProtocolParser::escape_csv(const std::string& s) {
    if (s.find_first_of(",\"\n") == std::string::npos) {
        return s;
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

void BaseProtocolParser::setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) {
    m_json_stream = json_stream;
    m_csv_stream = csv_stream;

    if (m_csv_stream && m_csv_stream->is_open()) {
        m_csv_stream->seekp(0, std::ios::end);
        if (m_csv_stream->tellp() == 0) {
            writeCsvHeader(*m_csv_stream);
        }
    }
}

void BaseProtocolParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,d\n";
}

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

void BaseProtocolParser::writeCsvLineAndCapture(const std::string& csv_line) {
    // CSV 파일에 쓰기
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << csv_line;
        m_csv_stream->flush(); // 즉시 flush
    }
    
    // TimeBasedWriter에도 전달
    if (m_time_writer) {
        // 줄바꿈 제거
        std::string trimmed = csv_line;
        while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r')) {
            trimmed.pop_back();
        }
        
        if (!trimmed.empty()) {
            m_time_writer->addRecord(getName(), trimmed);
        }
    }
}

void BaseProtocolParser::writeBaseCsvLine(const PacketInfo& info, const std::string& direction, const std::string& details_json_content) {
    if (m_csv_stream && m_csv_stream->is_open()) {
        std::stringstream ss;
        ss << info.timestamp << ","
           << info.src_mac << "," << info.dst_mac << ","
           << info.src_ip << "," << info.src_port << ","
           << info.dst_ip << "," << info.dst_port << ","
           << info.tcp_seq << "," << info.tcp_ack << "," << (int)info.tcp_flags << ","
           << direction << ","
           << escape_csv(details_json_content) << "\n";
        
        writeCsvLineAndCapture(ss.str());
    }
}