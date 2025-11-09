#ifndef REDIS_CACHE_H
#define REDIS_CACHE_H

#include <string>
#include <vector>
#include <memory>
#include <hiredis/hiredis.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Redis 캐시 설정
struct RedisCacheConfig {
    std::string host = "127.0.0.1";
    int port = 6379;
    std::string password = "";
    int db = 0;
    int timeout_ms = 1000;
    
    // Stream 설정
    int max_stream_length = 100000;  // 최대 메시지 수
    int batch_size = 100;             // ML 읽기 배치 크기
    
    // TTL 설정
    int asset_cache_ttl = 3600;       // 자산 정보 캐시 1시간
    int alert_ttl = 86400;            // 알람 24시간 보관
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

// 파싱된 패킷 데이터 (Redis에 저장할 구조)
struct ParsedPacketData {
    std::string timestamp;
    std::string protocol;
    
    // 네트워크 정보
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string src_mac;
    std::string dst_mac;
    
    // 자산 식별 정보 (CSV 기반)
    AssetInfo src_asset;
    AssetInfo dst_asset;
    
    // 프로토콜별 세부 정보 (JSON)
    json protocol_details;
    
    // ML/DL 피처
    json features;
    
    json toJson() const {
        return {
            {"timestamp", timestamp},
            {"protocol", protocol},
            {"src_ip", src_ip},
            {"dst_ip", dst_ip},
            {"src_port", src_port},
            {"dst_port", dst_port},
            {"src_mac", src_mac},
            {"dst_mac", dst_mac},
            {"src_asset", src_asset.toJson()},
            {"dst_asset", dst_asset.toJson()},
            {"protocol_details", protocol_details},
            {"features", features}
        };
    }
};

class RedisCache {
public:
    explicit RedisCache(const RedisCacheConfig& config);
    ~RedisCache();
    
    // 연결 관리
    bool connect();
    void disconnect();
    bool isConnected() const { return m_connected; }
    
    // === 1. 자산 정보 캐싱 (빠른 조회) ===
    bool cacheAssetInfo(const std::string& ip, const AssetInfo& info);
    AssetInfo getAssetInfo(const std::string& ip);
    
    // === 2. Redis Stream 기반 실시간 데이터 전송 ===
    // C++ → Redis Stream → ML/DL
    bool pushToStream(const std::string& stream_name, const ParsedPacketData& data);
    
    // ML/DL에서 배치 읽기 (비블로킹)
    std::vector<ParsedPacketData> readFromStream(
        const std::string& stream_name, 
        const std::string& consumer_group,
        const std::string& consumer_name,
        int count = 100
    );
    
    // === 3. ML/DL 결과 발행 (Pub/Sub) ===
    bool publishAlert(const std::string& channel, const json& alert);
    
    // === 4. 통계/메트릭 저장 ===
    bool incrementCounter(const std::string& key, int value = 1);
    long long getCounter(const std::string& key);
    
    // === 5. 프로토콜별 Stream 자동 생성 ===
    void createProtocolStreams();
    
private:
    RedisCacheConfig m_config;
    redisContext* m_context;
    bool m_connected;
    
    // Redis 명령 실행 헬퍼
    redisReply* executeCommand(const char* format, ...);
    void freeReply(redisReply* reply);
    
    // 재연결 로직
    bool reconnect();
    
    // 에러 처리
    void logError(const std::string& operation);
};

// === Redis Stream 키 네이밍 규칙 ===
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