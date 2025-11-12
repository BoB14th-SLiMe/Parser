#include "RedisCache.h"
#include <iostream>
#include <iomanip>  

RedisCache::RedisCache(const RedisCacheConfig& config)
    : m_config(config), m_pool(nullptr), m_async_writer(nullptr) {}

RedisCache::~RedisCache() {
    disconnect();
}

bool RedisCache::connect() {
    std::cout << "[RedisCache] Initializing Redis connection..." << std::endl;
    
    // Connection Pool 생성
    m_pool = std::make_unique<RedisConnectionPool>(
        m_config.host, 
        m_config.port, 
        m_config.pool_size,
        m_config.timeout_ms
    );
    
    // 연결 테스트
    RedisConnectionGuard guard(*m_pool);
    if (!guard) {
        std::cerr << "[RedisCache] ✗ Failed to acquire test connection" << std::endl;
        return false;
    }
    
    // 비밀번호 인증
    if (!m_config.password.empty()) {
        redisReply* reply = (redisReply*)redisCommand(
            guard.get(), "AUTH %s", m_config.password.c_str());
        
        if (!reply || reply->type == REDIS_REPLY_ERROR) {
            logError("auth", reply ? reply->str : "");
            freeReply(reply);
            return false;
        }
        freeReply(reply);
        std::cout << "[RedisCache] ✓ Authentication successful" << std::endl;
    }
    
    // DB 선택
    redisReply* reply = (redisReply*)redisCommand(
        guard.get(), "SELECT %d", m_config.db);
    
    if (!reply || reply->type == REDIS_REPLY_ERROR) {
        logError("select db", reply ? reply->str : "");
        freeReply(reply);
        return false;
    }
    freeReply(reply);
    
    std::cout << "[RedisCache] ✓ Connection pool ready: " << m_config.host 
              << ":" << m_config.port << " (DB " << m_config.db 
              << ", " << m_config.pool_size << " connections)" << std::endl;
    
    // Async Writer 시작
    m_async_writer = std::make_unique<RedisAsyncWriter>(
        *m_pool, 
        m_config.async_writers,
        m_config.async_queue_size
    );
    m_async_writer->start();
    
    std::cout << "[RedisCache] ✓ Async writer started (" 
              << m_config.async_writers << " threads, queue size=" 
              << m_config.async_queue_size << ")" << std::endl;
    
    std::cout << "[RedisCache] ✓✓✓ Fully initialized and ready!" << std::endl;
    return true;
}

void RedisCache::disconnect() {
    std::cout << "[RedisCache] Initiating shutdown..." << std::endl;
    
    // Async Writer 먼저 종료 (남은 데이터 flush)
    if (m_async_writer) {
        std::cout << "[RedisCache] Stopping async writer..." << std::endl;
        m_async_writer->stop();
        m_async_writer.reset();
        std::cout << "[RedisCache] ✓ Async writer stopped" << std::endl;
    }
    
    // Connection Pool 종료
    if (m_pool) {
        std::cout << "[RedisCache] Closing connection pool..." << std::endl;
        m_pool->shutdown();
        m_pool.reset();
        std::cout << "[RedisCache] ✓ Connection pool closed" << std::endl;
    }
    
    std::cout << "[RedisCache] ✓✓✓ Shutdown complete" << std::endl;
}

bool RedisCache::isConnected() const {
    return m_pool && m_pool->available() > 0;
}

// === 1. 자산 정보 캐싱 (비동기) ===
bool RedisCache::cacheAssetInfo(const std::string& ip, const AssetInfo& info) {
    if (!m_async_writer) {
        std::cerr << "[RedisCache] cacheAssetInfo: async writer not initialized" << std::endl;
        return false;
    }
    
    json j = info.toJson();
    return m_async_writer->cacheAsset(ip, j.dump(), m_config.asset_cache_ttl);
}

AssetInfo RedisCache::getAssetInfo(const std::string& ip) {
    AssetInfo info;
    
    if (!m_pool) {
        std::cerr << "[RedisCache] getAssetInfo: pool not initialized" << std::endl;
        return info;
    }
    
    RedisConnectionGuard guard(*m_pool);
    if (!guard) {
        std::cerr << "[RedisCache] getAssetInfo: failed to acquire connection" << std::endl;
        return info;
    }
    
    std::string key = RedisKeys::assetCache(ip);
    redisReply* reply = (redisReply*)redisCommand(guard.get(), "GET %s", key.c_str());
    
    if (reply && reply->type == REDIS_REPLY_STRING) {
        try {
            json j = json::parse(reply->str);
            info.ip = j.value("ip", "");
            info.mac = j.value("mac", "");
            info.asset_id = j.value("asset_id", "");
            info.asset_name = j.value("asset_name", "");
            info.group = j.value("group", "");
            info.location = j.value("location", "");
        } catch (const std::exception& e) {
            std::cerr << "[RedisCache] Failed to parse asset info for " << ip 
                      << ": " << e.what() << std::endl;
        }
    }
    
    freeReply(reply);
    return info;
}

// === 2. Redis Stream (비동기) ===
bool RedisCache::pushToStream(const std::string& stream_name,
                              const ParsedPacketData& data) {
    if (!m_async_writer) {
        std::cerr << "[RedisCache] pushToStream: async writer not initialized" << std::endl;
        return false;
    }

    // JSON 직렬화
    json j = data.toJson();
    std::string json_str = j.dump();

    // 비동기 쓰기 (즉시 리턴)
    bool success = m_async_writer->writeStream(stream_name, json_str);

    // 통계 카운터도 비동기로 증가
    if (success) {
        m_async_writer->incrCounter(RedisKeys::statsCounter(data.protocol));
    } else {
        std::cerr << "[Redis] ✗ Failed to queue stream write: " << stream_name << std::endl;
    }

    return success;
}

// === 3. Pub/Sub (동기 - Alert는 즉시 전송 필요) ===
bool RedisCache::publishAlert(const std::string& channel, const json& alert) {
    if (!m_pool) {
        std::cerr << "[RedisCache] publishAlert: pool not initialized" << std::endl;
        return false;
    }
    
    RedisConnectionGuard guard(*m_pool);
    if (!guard) {
        std::cerr << "[RedisCache] publishAlert: failed to acquire connection" << std::endl;
        return false;
    }
    
    std::string alert_str = alert.dump();
    redisReply* reply = (redisReply*)redisCommand(
        guard.get(),
        "PUBLISH %s %s",
        channel.c_str(),
        alert_str.c_str()
    );
    
    bool success = false;
    if (reply && reply->type == REDIS_REPLY_INTEGER) {
        success = true;
        std::cout << "[RedisCache] Alert published to " << channel 
                  << " (" << reply->integer << " subscribers)" << std::endl;
    } else {
        logError("publishAlert", reply && reply->str ? reply->str : "unknown error");
    }
    
    freeReply(reply);
    return success;
}

// === 4. 통계/메트릭 ===
bool RedisCache::incrementCounter(const std::string& key, int value) {
    if (!m_async_writer) {
        std::cerr << "[RedisCache] incrementCounter: async writer not initialized" << std::endl;
        return false;
    }
    
    // 비동기로 카운터 증가
    for (int i = 0; i < value; ++i) {
        m_async_writer->incrCounter(key);
    }
    
    return true;
}

long long RedisCache::getCounter(const std::string& key) {
    if (!m_pool) {
        std::cerr << "[RedisCache] getCounter: pool not initialized" << std::endl;
        return 0;
    }
    
    RedisConnectionGuard guard(*m_pool);
    if (!guard) {
        std::cerr << "[RedisCache] getCounter: failed to acquire connection" << std::endl;
        return 0;
    }
    
    redisReply* reply = (redisReply*)redisCommand(guard.get(), "GET %s", key.c_str());
    long long value = 0;
    
    if (reply && reply->type == REDIS_REPLY_STRING) {
        try {
            value = std::stoll(reply->str);
        } catch (const std::exception& e) {
            std::cerr << "[RedisCache] Failed to parse counter value: " << e.what() << std::endl;
            value = 0;
        }
    }
    
    freeReply(reply);
    return value;
}

// === 5. Stream 초기화 ===
void RedisCache::createProtocolStreams() {
    std::vector<std::string> protocols = {
        "modbus", "s7comm", "xgt_fen", "dnp3",
        "dns", "dhcp", "ethernet_ip", "iec104",
        "mms", "opc_ua", "bacnet", "arp", "tcp_session"
    };
    
    if (!m_pool) {
        std::cerr << "[RedisCache] createProtocolStreams: pool not initialized" << std::endl;
        return;
    }
    
    RedisConnectionGuard guard(*m_pool);
    if (!guard) {
        std::cerr << "[RedisCache] createProtocolStreams: failed to acquire connection" << std::endl;
        return;
    }
    
    std::cout << "[RedisCache] Initializing protocol streams..." << std::endl;
    
    int created_count = 0;
    for (const auto& protocol : protocols) {
        std::string stream_name = RedisKeys::protocolStream(protocol);
        
        // Stream 존재 여부 확인
        redisReply* reply = (redisReply*)redisCommand(
            guard.get(), "XINFO STREAM %s", stream_name.c_str());
        
        if (reply && reply->type == REDIS_REPLY_ERROR) {
            // Stream이 없으면 생성
            redisReply* create_reply = (redisReply*)redisCommand(
                guard.get(), "XADD %s * _init 1", stream_name.c_str());
            
            if (create_reply && create_reply->type != REDIS_REPLY_ERROR) {
                std::cout << "[RedisCache]   ✓ Created stream: " << stream_name << std::endl;
                created_count++;
            } else {
                std::cerr << "[RedisCache]   ✗ Failed to create stream: " << stream_name << std::endl;
            }
            
            freeReply(create_reply);
        }
        
        freeReply(reply);
    }
    
    std::cout << "[RedisCache] ✓ Stream initialization complete (" 
              << created_count << " created, " 
              << (protocols.size() - created_count) << " already exist)" << std::endl;
}

// === 통계 출력 ===
void RedisCache::printStats() const {
    std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
    std::cout << "│      Redis Cache Statistics         │" << std::endl;
    std::cout << "├─────────────────────────────────────┤" << std::endl;
    
    if (m_pool) {
        std::cout << "│ Connection Pool:                    │" << std::endl;
        std::cout << "│   Available: " << std::setw(2) << m_pool->available() 
                  << "/" << std::setw(2) << m_pool->capacity() << " connections     │" << std::endl;
    } else {
        std::cout << "│ Connection Pool: Not initialized    │" << std::endl;
    }
    
    if (m_async_writer) {
        auto stats = m_async_writer->getStats();
        std::cout << "│ Async Writer:                       │" << std::endl;
        std::cout << "│   Queue Size:  " << std::setw(8) << stats.queue_size << "          │" << std::endl;
        std::cout << "│   Total Written: " << std::setw(10) << stats.total_written << "      │" << std::endl;
        std::cout << "│   Total Dropped: " << std::setw(10) << stats.total_dropped << "      │" << std::endl;
        
        if (stats.total_written > 0) {
            double drop_rate = (double)stats.total_dropped / (stats.total_written + stats.total_dropped) * 100.0;
            std::cout << "│   Drop Rate:   " << std::fixed << std::setprecision(2) 
                      << std::setw(6) << drop_rate << "%            │" << std::endl;
        }
    } else {
        std::cout << "│ Async Writer: Not initialized       │" << std::endl;
    }
    
    std::cout << "└─────────────────────────────────────┘\n" << std::endl;
}

// === Helper 함수 ===
void RedisCache::freeReply(redisReply* reply) {
    if (reply) {
        freeReplyObject(reply);
    }
}

void RedisCache::logError(const std::string& operation, const std::string& details) {
    std::cerr << "[RedisCache Error] " << operation;
    if (!details.empty()) {
        std::cerr << ": " << details;
    }
    std::cerr << std::endl;
}