#include "BaseProtocolParser.h"
#include <sstream>
#include <iomanip>
#include <iostream>

// --- mac_to_string 정적 멤버 함수 구현 ---
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

// 기본 CSV 헤더 구현
void BaseProtocolParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,len\n";
}

// JSONL 작성 + Redis/ES 전송 헬퍼 함수 구현
void BaseProtocolParser::writeJsonl(const PacketInfo& info, const std::string& direction, const std::string& details_json_content) {
    // 1. JSONL 파일 쓰기
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

    // 2. Redis Stream으로 전송
    if (m_redis_cache && m_redis_cache->isConnected()) {
        try {
            ParsedPacketData data;
            data.timestamp = info.timestamp;
            data.protocol = getName();
            data.src_ip = info.src_ip;
            data.dst_ip = info.dst_ip;
            data.src_port = info.src_port;
            data.dst_port = info.dst_port;
            data.src_mac = info.src_mac;
            data.dst_mac = info.dst_mac;
            
            // protocol_details는 JSON 문자열을 파싱
            try {
                data.protocol_details = json::parse(details_json_content);
            } catch (const std::exception& e) {
                std::cerr << "[WARN] Failed to parse protocol details JSON for Redis: " 
                          << e.what() << std::endl;
                data.protocol_details = json::object();
            }
            
            // 자산 정보 조회
            data.src_asset = m_redis_cache->getAssetInfo(info.src_ip);
            data.dst_asset = m_redis_cache->getAssetInfo(info.dst_ip);
            
            // 간단한 피처 추출
            data.features = {
                {"payload_size", info.payload_size},
                {"tcp_flags", (int)info.tcp_flags},
                {"direction", direction}
            };
            
            // Redis Stream에 푸시
            std::string stream_name = RedisKeys::protocolStream(getName());
            if (!m_redis_cache->pushToStream(stream_name, data)) {
                std::cerr << "[WARN] Failed to push to Redis stream: " << stream_name << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Redis push exception: " << e.what() << std::endl;
        }
    }

    // 3. Elasticsearch로 전송
    if (m_elasticsearch && m_elasticsearch->isConnected()) {
        try {
            json doc;
            doc["@timestamp"] = info.timestamp;
            doc["protocol"] = getName();
            doc["src_ip"] = info.src_ip;
            doc["dst_ip"] = info.dst_ip;
            doc["src_port"] = info.src_port;
            doc["dst_port"] = info.dst_port;
            doc["src_mac"] = info.src_mac;
            doc["dst_mac"] = info.dst_mac;
            doc["direction"] = direction;
            doc["flow_id"] = info.flow_id;
            
            try {
                doc["protocol_details"] = json::parse(details_json_content);
            } catch (const std::exception& e) {
                std::cerr << "[WARN] Failed to parse protocol details JSON for ES: " 
                          << e.what() << std::endl;
                doc["protocol_details"] = json::object();
            }
            
            if (!m_elasticsearch->addToBulk(getName(), doc)) {
                std::cerr << "[WARN] Failed to add to Elasticsearch bulk: " << getName() << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Elasticsearch bulk add exception: " << e.what() << std::endl;
        }
    }
}