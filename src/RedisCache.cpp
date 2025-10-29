#include "RedisCache.h"
#include <iostream>
#include <cstdarg>

RedisCache::RedisCache(const RedisCacheConfig& config)
    : m_config(config), m_context(nullptr), m_connected(false) {}

RedisCache::~RedisCache() {
    disconnect();
}

bool RedisCache::connect() {
    struct timeval timeout = { m_config.timeout_ms / 1000, 
                               (m_config.timeout_ms % 1000) * 1000 };
    
    m_context = redisConnectWithTimeout(m_config.host.c_str(), 
                                        m_config.port, timeout);
    
    if (m_context == nullptr || m_context->err) {
        logError("connect");
        return false;
    }
    
    // 비밀번호 인증
    if (!m_config.password.empty()) {
        redisReply* reply = (redisReply*)redisCommand(m_context, 
                                                      "AUTH %s", 
                                                      m_config.password.c_str());
        if (reply == nullptr || reply->type == REDIS_REPLY_ERROR) {
            logError("auth");
            freeReply(reply);
            return false;
        }
        freeReply(reply);
    }
    
    // DB 선택
    redisReply* reply = (redisReply*)redisCommand(m_context, 
                                                  "SELECT %d", 
                                                  m_config.db);
    if (reply == nullptr || reply->type == REDIS_REPLY_ERROR) {
        logError("select db");
        freeReply(reply);
        return false;
    }
    freeReply(reply);
    
    m_connected = true;
    std::cout << "[Redis] Connected to " << m_config.host 
              << ":" << m_config.port << std::endl;
    
    createProtocolStreams();
    return true;
}

void RedisCache::disconnect() {
    if (m_context) {
        redisFree(m_context);
        m_context = nullptr;
    }
    m_connected = false;
}

bool RedisCache::reconnect() {
    disconnect();
    return connect();
}

// === 1. 자산 정보 캐싱 ===
bool RedisCache::cacheAssetInfo(const std::string& ip, const AssetInfo& info) {
    if (!isConnected() && !reconnect()) return false;
    
    std::string key = RedisKeys::assetCache(ip);
    json j = info.toJson();
    
    redisReply* reply = executeCommand(
        "SETEX %s %d %s",
        key.c_str(),
        m_config.asset_cache_ttl,
        j.dump().c_str()
    );
    
    bool success = (reply && reply->type != REDIS_REPLY_ERROR);
    freeReply(reply);
    return success;
}

AssetInfo RedisCache::getAssetInfo(const std::string& ip) {
    AssetInfo info;
    if (!isConnected() && !reconnect()) return info;
    
    std::string key = RedisKeys::assetCache(ip);
    redisReply* reply = executeCommand("GET %s", key.c_str());
    
    if (reply && reply->type == REDIS_REPLY_STRING) {
        try {
            json j = json::parse(reply->str);
            info.ip = j.value("ip", "");
            info.mac = j.value("mac", "");
            info.asset_id = j.value("asset_id", "");
            info.asset_name = j.value("asset_name", "");
            info.group = j.value("group", "");
            info.location = j.value("location", "");
        } catch (...) {
            std::cerr << "[Redis] Failed to parse asset info" << std::endl;
        }
    }
    
    freeReply(reply);
    return info;
}

// === 2. Redis Stream 기반 실시간 데이터 전송 ===
bool RedisCache::pushToStream(const std::string& stream_name, 
                              const ParsedPacketData& data) {
    if (!isConnected() && !reconnect()) return false;
    
    json j = data.toJson();
    std::string json_str = j.dump();
    
    // XADD stream_name MAXLEN ~ 100000 * data <json>
    redisReply* reply = executeCommand(
        "XADD %s MAXLEN ~ %d * data %s",
        stream_name.c_str(),
        m_config.max_stream_length,
        json_str.c_str()
    );
    
    bool success = (reply && reply->type != REDIS_REPLY_ERROR);
    freeReply(reply);
    
    if (success) {
        incrementCounter(RedisKeys::statsCounter(data.protocol));
    }
    
    return success;
}

std::vector<ParsedPacketData> RedisCache::readFromStream(
    const std::string& stream_name,
    const std::string& consumer_group,
    const std::string& consumer_name,
    int count) {
    
    std::vector<ParsedPacketData> results;
    if (!isConnected() && !reconnect()) return results;
    
    // Consumer Group 자동 생성 (없으면)
    redisReply* group_reply = executeCommand("XGROUP CREATE %s %s 0 MKSTREAM",
                                            stream_name.c_str(),
                                            consumer_group.c_str());
    freeReply(group_reply); // 에러 무시 (이미 존재하면 에러 발생)
    
    // XREADGROUP GROUP group consumer COUNT count BLOCK 100 STREAMS stream >
    redisReply* reply = executeCommand(
        "XREADGROUP GROUP %s %s COUNT %d BLOCK 100 STREAMS %s >",
        consumer_group.c_str(),
        consumer_name.c_str(),
        count,
        stream_name.c_str()
    );
    
    if (reply && reply->type == REDIS_REPLY_ARRAY) {
        // 응답 파싱 (복잡한 구조)
        // reply->element[0]->element[1] = 메시지 배열
        if (reply->elements > 0 && reply->element[0]->type == REDIS_REPLY_ARRAY) {
            redisReply* stream_data = reply->element[0];
            if (stream_data->elements > 1) {
                redisReply* messages = stream_data->element[1];
                
                for (size_t i = 0; i < messages->elements; ++i) {
                    redisReply* msg = messages->element[i];
                    if (msg->elements >= 2) {
                        // msg->element[0] = message ID
                        // msg->element[1] = field-value 배열
                        redisReply* fields = msg->element[1];
                        
                        // 변수명 충돌 수정: j -> field_idx
                        for (size_t field_idx = 0; field_idx < fields->elements; field_idx += 2) {
                            if (field_idx + 1 >= fields->elements) break; // 안전성 체크
                            
                            std::string field = fields->element[field_idx]->str;
                            if (field == "data") {
                                try {
                                    json parsed_json = json::parse(fields->element[field_idx + 1]->str);
                                    ParsedPacketData data;
                                    data.timestamp = parsed_json.value("timestamp", "");
                                    data.protocol = parsed_json.value("protocol", "");
                                    data.src_ip = parsed_json.value("src_ip", "");
                                    data.dst_ip = parsed_json.value("dst_ip", "");
                                    data.src_port = parsed_json.value("src_port", 0);
                                    data.dst_port = parsed_json.value("dst_port", 0);
                                    data.src_mac = parsed_json.value("src_mac", "");
                                    data.dst_mac = parsed_json.value("dst_mac", "");
                                    
                                    // 자산 정보 파싱
                                    if (parsed_json.contains("src_asset")) {
                                        auto& src_asset_json = parsed_json["src_asset"];
                                        data.src_asset.ip = src_asset_json.value("ip", "");
                                        data.src_asset.mac = src_asset_json.value("mac", "");
                                        data.src_asset.asset_id = src_asset_json.value("asset_id", "");
                                        data.src_asset.asset_name = src_asset_json.value("asset_name", "");
                                        data.src_asset.group = src_asset_json.value("group", "");
                                        data.src_asset.location = src_asset_json.value("location", "");
                                    }
                                    
                                    if (parsed_json.contains("dst_asset")) {
                                        auto& dst_asset_json = parsed_json["dst_asset"];
                                        data.dst_asset.ip = dst_asset_json.value("ip", "");
                                        data.dst_asset.mac = dst_asset_json.value("mac", "");
                                        data.dst_asset.asset_id = dst_asset_json.value("asset_id", "");
                                        data.dst_asset.asset_name = dst_asset_json.value("asset_name", "");
                                        data.dst_asset.group = dst_asset_json.value("group", "");
                                        data.dst_asset.location = dst_asset_json.value("location", "");
                                    }
                                    
                                    data.protocol_details = parsed_json.value("protocol_details", json::object());
                                    data.features = parsed_json.value("features", json::object());
                                    results.push_back(data);
                                } catch (const std::exception& e) {
                                    std::cerr << "[Redis] Failed to parse message: " << e.what() << std::endl;
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if (reply && reply->type == REDIS_REPLY_ERROR) {
        std::cerr << "[Redis] XREADGROUP error: " << reply->str << std::endl;
    }
    
    freeReply(reply);
    return results;
}

// === 3. ML/DL 결과 발행 (Pub/Sub) ===
bool RedisCache::publishAlert(const std::string& channel, const json& alert) {
    if (!isConnected() && !reconnect()) return false;
    
    redisReply* reply = executeCommand(
        "PUBLISH %s %s",
        channel.c_str(),
        alert.dump().c_str()
    );
    
    bool success = (reply && reply->type == REDIS_REPLY_INTEGER);
    freeReply(reply);
    return success;
}

// === 4. 통계/메트릭 저장 ===
bool RedisCache::incrementCounter(const std::string& key, int value) {
    if (!isConnected() && !reconnect()) return false;
    
    redisReply* reply = executeCommand("INCRBY %s %d", key.c_str(), value);
    bool success = (reply && reply->type == REDIS_REPLY_INTEGER);
    freeReply(reply);
    return success;
}

long long RedisCache::getCounter(const std::string& key) {
    if (!isConnected() && !reconnect()) return 0;
    
    redisReply* reply = executeCommand("GET %s", key.c_str());
    long long value = 0;
    
    if (reply && reply->type == REDIS_REPLY_STRING) {
        value = std::stoll(reply->str);
    }
    
    freeReply(reply);
    return value;
}

// === 5. 프로토콜별 Stream 자동 생성 ===
void RedisCache::createProtocolStreams() {
    std::vector<std::string> protocols = {
        "modbus_tcp", "s7comm", "xgt-fen", "dnp3", 
        "dns", "dhcp", "ethernet_ip", "iec104", 
        "mms", "opc_ua", "bacnet", "arp", "tcp_session"
    };
    
    for (const auto& protocol : protocols) {
        std::string stream_name = RedisKeys::protocolStream(protocol);
        // Stream 존재 확인 (XINFO STREAM)
        redisReply* reply = executeCommand("XINFO STREAM %s", stream_name.c_str());
        
        if (reply && reply->type == REDIS_REPLY_ERROR) {
            // Stream이 없으면 빈 메시지로 생성
            executeCommand("XADD %s * _init 1", stream_name.c_str());
            std::cout << "[Redis] Created stream: " << stream_name << std::endl;
        }
        
        freeReply(reply);
    }
}

// === Helper 함수 ===
redisReply* RedisCache::executeCommand(const char* format, ...) {
    va_list args;
    va_start(args, format);
    redisReply* reply = (redisReply*)redisvCommand(m_context, format, args);
    va_end(args);
    return reply;
}

void RedisCache::freeReply(redisReply* reply) {
    if (reply) {
        freeReplyObject(reply);
    }
}

void RedisCache::logError(const std::string& operation) {
    if (m_context && m_context->err) {
        std::cerr << "[Redis Error] " << operation << ": " 
                  << m_context->errstr << std::endl;
    } else {
        std::cerr << "[Redis Error] " << operation << ": Connection failed" << std::endl;
    }
}