#ifndef REDIS_CONNECTION_POOL_H
#define REDIS_CONNECTION_POOL_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <hiredis/hiredis.h>
#include <iostream>
#include <chrono>

// 단일 Redis 연결
class RedisConnection {
public:
    redisContext* context;
    bool valid;
    std::chrono::steady_clock::time_point last_used;
    
    RedisConnection(const std::string& host, int port, int timeout_ms) {
        struct timeval timeout = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        context = redisConnectWithTimeout(host.c_str(), port, timeout);
        valid = (context && !context->err);
        last_used = std::chrono::steady_clock::now();
        
        if (valid) {
            std::cout << "[RedisConn] ✓ Connected to " << host << ":" << port << std::endl;
        } else {
            std::cerr << "[RedisConn] ✗ Connection failed: " 
                      << (context ? context->errstr : "null context") << std::endl;
        }
    }
    
    ~RedisConnection() {
        if (context) {
            redisFree(context);
            context = nullptr;
        }
    }
    
    bool isValid() {
        if (!context || context->err) {
            valid = false;
            return false;
        }
        
        // Ping 테스트
        redisReply* reply = (redisReply*)redisCommand(context, "PING");
        if (!reply || reply->type == REDIS_REPLY_ERROR) {
            valid = false;
            if (reply) freeReplyObject(reply);
            return false;
        }
        
        freeReplyObject(reply);
        last_used = std::chrono::steady_clock::now();
        return true;
    }
};

// Connection Pool
class RedisConnectionPool {
public:
    RedisConnectionPool(const std::string& host, int port, 
                       int pool_size = 8, int timeout_ms = 1000)
        : m_host(host), m_port(port), m_timeout_ms(timeout_ms), 
          m_pool_size(pool_size), m_shutdown(false) {
        
        std::cout << "[RedisPool] Initializing " << pool_size << " connections..." << std::endl;
        
        for (int i = 0; i < pool_size; ++i) {
            auto conn = std::make_unique<RedisConnection>(host, port, timeout_ms);
            if (conn->valid) {
                m_pool.push(std::move(conn));
            }
        }
        
        std::cout << "[RedisPool] ✓ Ready with " << m_pool.size() 
                  << "/" << pool_size << " connections" << std::endl;
    }
    
    ~RedisConnectionPool() {
        shutdown();
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
        m_cv.notify_all();
        
        while (!m_pool.empty()) {
            m_pool.pop();
        }
    }
    
    std::unique_ptr<RedisConnection> acquire(int timeout_ms = 5000) {
        std::unique_lock<std::mutex> lock(m_mutex);
        
        if (m_shutdown) return nullptr;
        
        auto deadline = std::chrono::steady_clock::now() + 
                       std::chrono::milliseconds(timeout_ms);
        
        if (!m_cv.wait_until(lock, deadline, [this] { 
            return !m_pool.empty() || m_shutdown; 
        })) {
            std::cerr << "[RedisPool] ⚠️ Acquire timeout (" << timeout_ms << "ms)" << std::endl;
            
            // 긴급 연결 생성
            auto emergency = std::make_unique<RedisConnection>(m_host, m_port, m_timeout_ms);
            if (emergency->valid) {
                std::cout << "[RedisPool] Created emergency connection" << std::endl;
                return emergency;
            }
            return nullptr;
        }
        
        if (m_shutdown || m_pool.empty()) return nullptr;
        
        auto conn = std::move(m_pool.front());
        m_pool.pop();
        
        if (!conn->isValid()) {
            std::cerr << "[RedisPool] Invalid connection, recreating..." << std::endl;
            conn = std::make_unique<RedisConnection>(m_host, m_port, m_timeout_ms);
        }
        
        return conn;
    }
    
    void release(std::unique_ptr<RedisConnection> conn) {
        if (!conn) return;
        
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_shutdown) return;
        
        if (conn->isValid()) {
            m_pool.push(std::move(conn));
            m_cv.notify_one();
        } else {
            auto new_conn = std::make_unique<RedisConnection>(m_host, m_port, m_timeout_ms);
            if (new_conn->valid) {
                m_pool.push(std::move(new_conn));
                m_cv.notify_one();
            }
        }
    }
    
    size_t available() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pool.size();
    }
    
    size_t capacity() const { return m_pool_size; }

private:
    std::string m_host;
    int m_port;
    int m_timeout_ms;
    int m_pool_size;
    bool m_shutdown;
    
    std::queue<std::unique_ptr<RedisConnection>> m_pool;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
};

// RAII 래퍼
class RedisConnectionGuard {
public:
    RedisConnectionGuard(RedisConnectionPool& pool, int timeout_ms = 5000) 
        : m_pool(pool), m_conn(pool.acquire(timeout_ms)) {}
    
    ~RedisConnectionGuard() {
        if (m_conn) {
            m_pool.release(std::move(m_conn));
        }
    }
    
    RedisConnectionGuard(const RedisConnectionGuard&) = delete;
    RedisConnectionGuard& operator=(const RedisConnectionGuard&) = delete;
    
    redisContext* get() { return m_conn ? m_conn->context : nullptr; }
    bool isValid() const { return m_conn && m_conn->valid; }
    explicit operator bool() const { return isValid(); }

private:
    RedisConnectionPool& m_pool;
    std::unique_ptr<RedisConnection> m_conn;
};

#endif // REDIS_CONNECTION_POOL_H