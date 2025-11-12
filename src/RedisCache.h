#ifndef REDIS_CACHE_H
#define REDIS_CACHE_H

#include <string>
#include <vector>
#include <memory>
#include <hiredis/hiredis.h>
#include <nlohmann/json.hpp>
#include "RedisConnectionPool.h"
#include "RedisAsyncWriter.h"

using json = nlohmann::json;

// Redis 캐시 설정
struct RedisCacheConfig {
    std::string host = "127.0.0.1";
    int port = 6379;
    std::string password = "";
    int db = 0;
    int timeout_ms = 1000;
    
    // Connection Pool 설정
    int pool_size = 8;
    
    // Async Writer 설정
    int async_writers = 2;
    int async_queue_size = 10000;
    
    // Stream 설정
    int max_stream_length = 100000;
    
    // TTL 설정
    int asset_cache_ttl = 3600;
    int alert_ttl = 86400;
};

// 자산 식별 정보
struct AssetInfo {
    std::string ip;
    std::string mac;
    std::string asset_id;
    std::string asset_name;
    std::string group;
    std::string location;
    
    json toJson() const {
        return {
            {"ip", ip},
            {"mac", mac},
            {"asset_id", asset_id},
            {"asset_name", asset_name},
            {"group", group},
            {"location", location}
        };
    }
};

// 파싱된 패킷 데이터 (JSONL 출력 형식과 동일)
struct ParsedPacketData {
    std::string timestamp;
    std::string protocol;

    // JSONL 형식과 동일한 짧은 필드명 사용
    std::string smac;  // src_mac
    std::string dmac;  // dst_mac
    std::string sip;   // src_ip
    std::string sp;    // src_port
    std::string dip;   // dst_ip
    std::string dp;    // dst_port
    std::string sq;    // TCP sequence number
    std::string ak;    // TCP acknowledgement
    std::string fl;    // TCP flags
    std::string dir;   // direction

    // 자산 정보
    std::string src_asset_id;
    std::string src_asset_name;
    std::string src_asset_group;
    std::string src_asset_location;
    std::string dst_asset_id;
    std::string dst_asset_name;
    std::string dst_asset_group;
    std::string dst_asset_location;

    json protocol_details;  // JSONL에서는 "d"로 저장

    json toJson() const {
        json j = {
            {"@timestamp", timestamp},
            {"protocol", protocol},
            {"smac", smac},
            {"dmac", dmac},
            {"sip", sip},
            {"dip", dip},
            {"sp", sp},
            {"dp", dp},
            {"sq", sq},
            {"ak", ak},
            {"fl", fl},
            {"dir", dir}
        };

        // 자산 정보 추가 (문자열로만, IP 정보 제외)
        if (!src_asset_name.empty()) {
            j["src_asset"] = src_asset_name;
        }
        if (!dst_asset_name.empty()) {
            j["dst_asset"] = dst_asset_name;
        }

        // protocol_details를 "d"로 저장
        if (!protocol_details.empty()) {
            j["d"] = protocol_details;
        }

        return j;
    }
};

class RedisCache {
public:
    explicit RedisCache(const RedisCacheConfig& config);
    ~RedisCache();
    
    // 연결 관리
    bool connect();
    void disconnect();
    bool isConnected() const;
    
    // === 1. 자산 정보 캐싱 (비동기) ===
    bool cacheAssetInfo(const std::string& ip, const AssetInfo& info);
    AssetInfo getAssetInfo(const std::string& ip);  // 동기 읽기
    
    // === 2. Redis Stream (비동기) ===
    bool pushToStream(const std::string& stream_name, const ParsedPacketData& data);
    
    // === 3. Pub/Sub (비동기) ===
    bool publishAlert(const std::string& channel, const json& alert);
    
    // === 4. 통계/메트릭 (비동기) ===
    bool incrementCounter(const std::string& key, int value = 1);
    long long getCounter(const std::string& key);  // 동기 읽기
    
    // === 5. Stream 관리 ===
    void createProtocolStreams();
    
    // 통계
    void printStats() const;

private:
    RedisCacheConfig m_config;
    std::unique_ptr<RedisConnectionPool> m_pool;
    std::unique_ptr<RedisAsyncWriter> m_async_writer;
    
    static void freeReply(redisReply* reply);
    void logError(const std::string& operation, const std::string& details = "");
};

// Redis 키 네이밍
namespace RedisKeys {
    inline std::string protocolStream(const std::string& protocol) {
        return "stream:protocol:" + protocol;
    }
    
    inline std::string assetCache(const std::string& ip) {
        return "cache:asset:" + ip;
    }
    
    inline std::string alertChannel() {
        return "channel:alerts";
    }
    
    inline std::string statsCounter(const std::string& protocol) {
        return "stats:count:" + protocol;
    }
}

#endif // REDIS_CACHE_H