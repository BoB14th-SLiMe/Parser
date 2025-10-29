#ifndef BASE_PROTOCOL_PARSER_H
#define BASE_PROTOCOL_PARSER_H

#include "IProtocolParser.h"
#include "../RedisCache.h"
#include "../ElasticsearchClient.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class BaseProtocolParser : public IProtocolParser {
public:
    virtual ~BaseProtocolParser();

    static std::string mac_to_string(const uint8_t* mac);
    
    void setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) override;
    void setTimeBasedWriter(TimeBasedCsvWriter* writer) override { m_time_based_writer = writer; }
    
    // Redis/ES 설정
    void setRedisCache(RedisCache* redis_cache) { m_redis_cache = redis_cache; }
    void setElasticsearch(ElasticsearchClient* es_client) { m_elasticsearch = es_client; }

    bool isProtocol(const PacketInfo& /*info*/) const override { return false; }

    // 가상 함수로 선언 (각 파서가 오버라이드)
    virtual void writeCsvHeader(std::ofstream& csv_stream) override;

protected:
    // JSONL 작성 헬퍼 함수
    void writeJsonl(const PacketInfo& info, const std::string& direction, const std::string& details_json_content);

    // CSV 이스케이프 처리
    std::string escape_csv(const std::string& s);

    std::ofstream* m_json_stream = nullptr;
    std::ofstream* m_csv_stream = nullptr;
    TimeBasedCsvWriter* m_time_based_writer = nullptr;
    RedisCache* m_redis_cache = nullptr;
    ElasticsearchClient* m_elasticsearch = nullptr;
};

#endif // BASE_PROTOCOL_PARSER_H