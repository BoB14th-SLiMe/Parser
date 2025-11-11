#ifndef REDIS_ASYNC_WRITER_H
#define REDIS_ASYNC_WRITER_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <vector>
#include <hiredis/hiredis.h>
#include <nlohmann/json.hpp>
#include "RedisConnectionPool.h"

using json = nlohmann::json;

// Forward declarations
struct AssetInfo;
struct ParsedPacketData;

// 비동기 Redis Writer
class RedisAsyncWriter {
public:
    struct WriteTask {
        enum Type { STREAM_WRITE, COUNTER_INCR, ASSET_CACHE };
        
        Type type;
        std::string key;
        std::string value;
        std::string json_data;
        
        static WriteTask streamWrite(const std::string& stream, const std::string& json_str) {
            WriteTask task;
            task.type = STREAM_WRITE;
            task.key = stream;
            task.json_data = json_str;
            return task;
        }
        
        static WriteTask counterIncr(const std::string& counter) {
            WriteTask task;
            task.type = COUNTER_INCR;
            task.key = counter;
            return task;
        }
        
        static WriteTask assetCache(const std::string& ip, const std::string& json_str, int ttl) {
            WriteTask task;
            task.type = ASSET_CACHE;
            task.key = ip;
            task.json_data = json_str;
            task.value = std::to_string(ttl);
            return task;
        }
    };
    
    RedisAsyncWriter(RedisConnectionPool& pool, 
                     int num_writers = 2,
                     int queue_size = 10000)
        : m_pool(pool)
        , m_num_writers(num_writers)
        , m_max_queue_size(queue_size)
        , m_running(false)
        , m_total_written(0)
        , m_total_dropped(0) {}
    
    ~RedisAsyncWriter() {
        stop();
    }
    
    void start() {
        if (m_running) return;
        
        m_running = true;
        
        for (int i = 0; i < m_num_writers; ++i) {
            m_writers.emplace_back(&RedisAsyncWriter::writerWorker, this, i);
        }
        
        std::cout << "[AsyncWriter] Started " << m_num_writers 
                  << " writer threads (queue=" << m_max_queue_size << ")" << std::endl;
    }
    
    void stop() {
        if (!m_running) return;
        
        std::cout << "[AsyncWriter] Stopping..." << std::endl;
        m_running = false;
        m_cv.notify_all();
        
        for (auto& thread : m_writers) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        std::cout << "[AsyncWriter] Stopped. Written=" << m_total_written 
                  << ", Dropped=" << m_total_dropped 
                  << ", Remaining=" << queueSize() << std::endl;
    }
    
    bool enqueue(WriteTask&& task) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_queue.size() >= m_max_queue_size) {
            m_total_dropped++;
            
            if (m_total_dropped % 1000 == 1) {
                std::cerr << "[AsyncWriter] ⚠️ Queue full! Dropped=" << m_total_dropped << std::endl;
            }
            return false;
        }
        
        m_queue.push(std::move(task));
        m_cv.notify_one();
        return true;
    }
    
    bool writeStream(const std::string& stream, const std::string& json_data) {
        return enqueue(WriteTask::streamWrite(stream, json_data));
    }
    
    bool incrCounter(const std::string& counter) {
        return enqueue(WriteTask::counterIncr(counter));
    }
    
    bool cacheAsset(const std::string& ip, const std::string& json_data, int ttl) {
        return enqueue(WriteTask::assetCache(ip, json_data, ttl));
    }
    
    struct Stats {
        size_t queue_size;
        size_t total_written;
        size_t total_dropped;
    };
    
    Stats getStats() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return { m_queue.size(), m_total_written.load(), m_total_dropped.load() };
    }
    
    size_t queueSize() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }

private:
    RedisConnectionPool& m_pool;
    int m_num_writers;
    size_t m_max_queue_size;
    
    std::queue<WriteTask> m_queue;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    
    std::vector<std::thread> m_writers;
    std::atomic<bool> m_running;
    
    std::atomic<size_t> m_total_written;
    std::atomic<size_t> m_total_dropped;
    
    void writerWorker(int worker_id) {
        std::cout << "[AsyncWriter-" << worker_id << "] Started" << std::endl;
        
        std::vector<WriteTask> batch;
        batch.reserve(50);
        
        size_t local_written = 0;
        auto last_log = std::chrono::steady_clock::now();
        
        while (m_running) {
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                
                m_cv.wait_for(lock, std::chrono::milliseconds(100), [this] {
                    return !m_queue.empty() || !m_running;
                });
                
                if (!m_running && m_queue.empty()) break;
                
                while (!m_queue.empty() && batch.size() < 50) {
                    batch.push_back(std::move(m_queue.front()));
                    m_queue.pop();
                }
            }
            
            if (batch.empty()) continue;
            
            RedisConnectionGuard guard(m_pool, 1000);
            if (!guard) {
                std::cerr << "[AsyncWriter-" << worker_id << "] No connection" << std::endl;
                
                std::lock_guard<std::mutex> lock(m_mutex);
                for (auto& task : batch) {
                    if (m_queue.size() < m_max_queue_size) {
                        m_queue.push(std::move(task));
                    } else {
                        m_total_dropped++;
                    }
                }
                batch.clear();
                continue;
            }
            
            size_t written = processBatch(guard.get(), batch);
            local_written += written;
            m_total_written += written;
            batch.clear();
            
            // 10초마다 통계 출력
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_log).count() >= 10) {
                std::cout << "[AsyncWriter-" << worker_id << "] Written=" << local_written 
                          << ", Queue=" << queueSize() << std::endl;
                local_written = 0;
                last_log = now;
            }
        }
        
        std::cout << "[AsyncWriter-" << worker_id << "] Stopped" << std::endl;
    }
    
    size_t processBatch(redisContext* ctx, const std::vector<WriteTask>& batch) {
        for (const auto& task : batch) {
            switch (task.type) {
                case WriteTask::STREAM_WRITE:
                    redisAppendCommand(ctx,
                        "XADD %s MAXLEN ~ 100000 * data %s",
                        task.key.c_str(),
                        task.json_data.c_str()
                    );
                    break;
                
                case WriteTask::COUNTER_INCR:
                    redisAppendCommand(ctx, "INCRBY %s 1", task.key.c_str());
                    break;
                
                case WriteTask::ASSET_CACHE:
                    redisAppendCommand(ctx,
                        "SETEX cache:asset:%s %s %s",
                        task.key.c_str(),
                        task.value.c_str(),
                        task.json_data.c_str()
                    );
                    break;
            }
        }
        
        size_t success = 0;
        for (size_t i = 0; i < batch.size(); ++i) {
            redisReply* reply = nullptr;
            if (redisGetReply(ctx, (void**)&reply) == REDIS_OK) {
                if (reply && reply->type != REDIS_REPLY_ERROR) {
                    success++;
                }
                if (reply) freeReplyObject(reply);
            }
        }
        
        return success;
    }
};

#endif // REDIS_ASYNC_WRITER_H