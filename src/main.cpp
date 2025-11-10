#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <csignal>
#include <chrono>
#include <random>
#include <iomanip>
#include <pcap.h>
#include "RedisCache.h"

// ============================================================================
// 전역 변수
// ============================================================================
std::atomic<bool> g_running{true};
RedisCache* g_redis_cache = nullptr;

// ============================================================================
// 패킷 큐 (Thread-Safe)
// ============================================================================
template<typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue(size_t max_size = 10000) : m_max_size(max_size) {}
    
    bool push(T&& item, int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(m_mutex);
        
        if (!m_cv_push.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                [this] { return m_queue.size() < m_max_size; })) {
            return false;  // Timeout or full
        }
        
        m_queue.push(std::move(item));
        m_cv_pop.notify_one();
        return true;
    }
    
    bool pop(T& item, int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(m_mutex);
        
        if (!m_cv_pop.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                               [this] { return !m_queue.empty(); })) {
            return false;  // Timeout or empty
        }
        
        item = std::move(m_queue.front());
        m_queue.pop();
        m_cv_push.notify_one();
        return true;
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }
    
    bool empty() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty();
    }

private:
    std::queue<T> m_queue;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv_push;
    std::condition_variable m_cv_pop;
    size_t m_max_size;
};

// 전역 패킷 큐
ThreadSafeQueue<ParsedPacketData> g_packet_queue(10000);

// ============================================================================
// Signal 핸들러
// ============================================================================
void signalHandler(int signal) {
    std::cout << "\n[Main] Received signal " << signal << ", initiating shutdown..." << std::endl;
    g_running = false;
}

// ============================================================================
// 패킷 생성기 (시뮬레이션용)
// ============================================================================
class PacketGenerator {
public:
    PacketGenerator() : m_rng(std::random_device{}()) {}
    
    ParsedPacketData generatePacket() {
        ParsedPacketData packet;
        
        // 타임스탬프
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        char buffer[32];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", std::gmtime(&time_t));
        packet.timestamp = std::string(buffer) + "." + std::to_string(ms.count()) + "Z";
        
        // 프로토콜 랜덤 선택
        static const std::vector<std::string> protocols = {
            "modbus_tcp", "s7comm", "xgt-fen", "mms", "dnp3", 
            "ethernet_ip", "iec104", "opc_ua"
        };
        packet.protocol = protocols[m_rng() % protocols.size()];
        
        // IP 주소 생성
        packet.src_ip = "192.168.10." + std::to_string(10 + (m_rng() % 80));
        packet.dst_ip = "192.168.10." + std::to_string(10 + (m_rng() % 80));
        
        // 포트
        packet.src_port = 1024 + (m_rng() % 64000);
        packet.dst_port = getProtocolPort(packet.protocol);
        
        // MAC 주소
        packet.src_mac = generateMacAddress();
        packet.dst_mac = generateMacAddress();
        
        // 프로토콜별 상세 정보
        packet.protocol_details = generateProtocolDetails(packet.protocol);
        
        // Features (ML용)
        packet.features = {
            {"packet_size", 64 + (m_rng() % 1400)},
            {"flow_duration", (m_rng() % 10000)},
            {"packet_rate", (m_rng() % 1000)}
        };
        
        return packet;
    }

private:
    std::mt19937 m_rng;
    
    uint16_t getProtocolPort(const std::string& protocol) {
        if (protocol == "modbus_tcp") return 502;
        if (protocol == "s7comm") return 102;
        if (protocol == "dnp3") return 20000;
        if (protocol == "opc_ua") return 4840;
        return 1024 + (m_rng() % 64000);
    }
    
    std::string generateMacAddress() {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                m_rng() % 256, m_rng() % 256, m_rng() % 256,
                m_rng() % 256, m_rng() % 256, m_rng() % 256);
        return std::string(mac);
    }
    
    json generateProtocolDetails(const std::string& protocol) {
        json details;
        
        if (protocol == "modbus_tcp") {
            details = {
                {"tid", m_rng() % 65536},
                {"pdu", {
                    {"fc", 3 + (m_rng() % 3)},  // Function code 3-5
                    {"bc", (m_rng() % 100)},
                    {"regs", {{std::to_string(m_rng() % 100), m_rng() % 65536}}}
                }}
            };
        } else if (protocol == "s7comm") {
            details = {
                {"pdu_type", m_rng() % 3 + 1},
                {"function", m_rng() % 8},
                {"item_count", m_rng() % 10}
            };
        } else if (protocol == "xgt-fen") {
            details = {
                {"hdr", {
                    {"companyId", "LSIS-XGT"},
                    {"cpuInfo", 160},
                    {"invokeId", m_rng() % 65536},
                    {"len", 14 + (m_rng() % 100)}
                }},
                {"inst", {
                    {"cmd", 84 + (m_rng() % 2)},
                    {"dtype", 20},
                    {"dataSize", m_rng() % 100}
                }}
            };
        } else if (protocol == "mms") {
            details = {
                {"len", m_rng() % 256},
                {"operation", m_rng() % 10}
            };
        }
        
        return details;
    }
};

// ============================================================================
// 패킷 캡처 스레드 (실제 환경에서는 pcap 사용)
// ============================================================================
void captureThread() {
    std::cout << "[Capture] Started packet capture simulation" << std::endl;
    
    PacketGenerator generator;
    size_t total_captured = 0;
    size_t total_dropped = 0;
    auto last_log = std::chrono::steady_clock::now();
    
    while (g_running) {
        // 패킷 생성 (실제로는 pcap_next_ex() 등 사용)
        ParsedPacketData packet = generator.generatePacket();
        
        // 큐에 추가
        if (g_packet_queue.push(std::move(packet), 10)) {
            total_captured++;
        } else {
            total_dropped++;
        }
        
        // 패킷 생성 속도 조절 (실제로는 네트워크 속도에 따라)
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        
        // 10초마다 통계
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_log).count() >= 10) {
            std::cout << "[Capture] Captured=" << total_captured 
                      << ", Dropped=" << total_dropped 
                      << ", Queue=" << g_packet_queue.size() << std::endl;
            total_captured = 0;
            total_dropped = 0;
            last_log = now;
        }
    }
    
    std::cout << "[Capture] Stopped" << std::endl;
}

// ============================================================================
// Worker 스레드 (패킷 처리)
// ============================================================================
void workerThread(int worker_id, RedisCache& redis_cache) {
    std::cout << "[Worker-" << worker_id << "] Started" << std::endl;
    
    size_t processed = 0;
    size_t failed = 0;
    auto last_log = std::chrono::steady_clock::now();
    
    while (g_running || !g_packet_queue.empty()) {
        ParsedPacketData packet;
        
        // 큐에서 패킷 가져오기
        if (!g_packet_queue.pop(packet, 100)) {
            continue;  // Timeout or empty
        }
        
        // === 핵심: Redis에 비동기 쓰기 ===
        std::string stream_name = RedisKeys::protocolStream(packet.protocol);
        
        if (redis_cache.pushToStream(stream_name, packet)) {
            processed++;
        } else {
            failed++;
            
            if (failed % 100 == 1) {
                std::cerr << "[Worker-" << worker_id << "] ⚠️ Redis write failed! Count=" 
                          << failed << std::endl;
            }
        }
        
        // 10초마다 통계
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_log).count() >= 10) {
            std::cout << "[Worker-" << worker_id << "] Processed=" << processed 
                      << ", Failed=" << failed << std::endl;
            processed = 0;
            failed = 0;
            last_log = now;
        }
    }
    
    std::cout << "[Worker-" << worker_id << "] Stopped (processed remaining packets)" << std::endl;
}

// ============================================================================
// 통계 출력 스레드
// ============================================================================
void statsThread(RedisCache& redis_cache) {
    std::cout << "[Stats] Started statistics monitoring" << std::endl;
    
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        if (!g_running) break;
        
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "=== System Statistics at " 
                  << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) 
                  << " ===" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        
        // Redis 통계
        redis_cache.printStats();
        
        // 패킷 큐 상태
        std::cout << "Packet Queue Size: " << g_packet_queue.size() << std::endl;
        
        // 프로토콜별 패킷 수
        std::cout << "\nProtocol Statistics:" << std::endl;
        std::vector<std::string> protocols = {
            "modbus_tcp", "s7comm", "xgt-fen", "mms", "dnp3", 
            "ethernet_ip", "iec104", "opc_ua"
        };
        
        long long total_packets = 0;
        for (const auto& protocol : protocols) {
            long long count = redis_cache.getCounter(RedisKeys::statsCounter(protocol));
            if (count > 0) {
                std::cout << "  " << std::setw(15) << std::left << protocol 
                          << ": " << std::setw(10) << std::right << count << " packets" << std::endl;
                total_packets += count;
            }
        }
        
        std::cout << "  " << std::string(15, '-') << "   " << std::string(10, '-') << std::endl;
        std::cout << "  " << std::setw(15) << std::left << "TOTAL" 
                  << ": " << std::setw(10) << std::right << total_packets << " packets" << std::endl;
        
        std::cout << std::string(60, '=') << "\n" << std::endl;
    }
    
    std::cout << "[Stats] Stopped" << std::endl;
}

// ============================================================================
// Main 함수
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "===   Industrial Packet Parser with Redis (Async)   ===" << std::endl;
    std::cout << std::string(60, '=') << "\n" << std::endl;
    
    // Signal 핸들러 등록
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Redis 설정
    RedisCacheConfig redis_config;
    redis_config.host = "127.0.0.1";
    redis_config.port = 6379;
    redis_config.db = 0;
    redis_config.pool_size = 8;           // Worker 수와 동일
    redis_config.async_writers = 2;       // 비동기 Writer 2개
    redis_config.async_queue_size = 10000; // 큐 크기
    
    std::cout << "[Main] Configuration:" << std::endl;
    std::cout << "  Redis: " << redis_config.host << ":" << redis_config.port << std::endl;
    std::cout << "  Connection Pool: " << redis_config.pool_size << " connections" << std::endl;
    std::cout << "  Async Writers: " << redis_config.async_writers << " threads" << std::endl;
    std::cout << "  Queue Size: " << redis_config.async_queue_size << std::endl;
    std::cout << std::endl;
    
    // Redis 초기화
    RedisCache redis_cache(redis_config);
    g_redis_cache = &redis_cache;
    
    std::cout << "[Main] Connecting to Redis..." << std::endl;
    if (!redis_cache.connect()) {
        std::cerr << "[Main] ✗✗✗ Redis connection failed!" << std::endl;
        return 1;
    }
    
    // Stream 초기화
    std::cout << "[Main] Initializing protocol streams..." << std::endl;
    redis_cache.createProtocolStreams();
    
    // 스레드 시작
    int num_workers = 8;
    std::vector<std::thread> workers;
    
    std::cout << "\n[Main] Starting threads..." << std::endl;
    
    // Capture 스레드
    std::thread capture_thread(captureThread);
    
    // Worker 스레드들
    std::cout << "[Main] Starting " << num_workers << " worker threads..." << std::endl;
    for (int i = 0; i < num_workers; ++i) {
        workers.emplace_back(workerThread, i, std::ref(redis_cache));
    }
    
    // 통계 스레드
    std::thread stats_thread(statsThread, std::ref(redis_cache));
    
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "===          System is running. Press Ctrl+C to stop         ===" << std::endl;
    std::cout << std::string(60, '=') << "\n" << std::endl;
    
    // 메인 루프 (간단한 모니터링)
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // 종료 시작
    std::cout << "\n[Main] Shutdown initiated..." << std::endl;
    std::cout << "[Main] Waiting for capture thread..." << std::endl;
    if (capture_thread.joinable()) {
        capture_thread.join();
    }
    
    std::cout << "[Main] Waiting for worker threads to finish remaining packets..." << std::endl;
    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    std::cout << "[Main] Waiting for stats thread..." << std::endl;
    if (stats_thread.joinable()) {
        stats_thread.join();
    }
    
    // 최종 통계
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "===              Final Statistics                    ===" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    redis_cache.printStats();
    
    std::cout << "\nProtocol Summary:" << std::endl;
    std::vector<std::string> protocols = {
        "modbus_tcp", "s7comm", "xgt-fen", "mms", "dnp3", 
        "ethernet_ip", "iec104", "opc_ua"
    };
    
    long long grand_total = 0;
    for (const auto& protocol : protocols) {
        long long count = redis_cache.getCounter(RedisKeys::statsCounter(protocol));
        if (count > 0) {
            std::cout << "  " << std::setw(15) << std::left << protocol 
                      << ": " << std::setw(10) << std::right << count << std::endl;
            grand_total += count;
        }
    }
    std::cout << "  " << std::string(15, '-') << "   " << std::string(10, '-') << std::endl;
    std::cout << "  " << std::setw(15) << std::left << "TOTAL PROCESSED" 
              << ": " << std::setw(10) << std::right << grand_total << std::endl;
    
    // Redis 연결 종료
    std::cout << "\n[Main] Disconnecting from Redis..." << std::endl;
    redis_cache.disconnect();
    
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "===           Shutdown complete. Goodbye!            ===" << std::endl;
    std::cout << std::string(60, '=') << "\n" << std::endl;
    
    return 0;
}

/*
==============================================================================
컴파일 방법:
==============================================================================

g++ -o parser main.cpp RedisCache.cpp \
    -std=c++17 -pthread \
    -lhiredis -lpcap \
    -I/usr/include/nlohmann \
    -O2 -Wall -Wextra

==============================================================================
실행 방법:
==============================================================================

1. Redis 실행 확인:
   redis-cli ping

2. 파서 실행:
   ./parser

3. 모니터링 (다른 터미널):
   redis-cli MONITOR
   redis-cli INFO stats
   redis-cli XLEN stream:protocol:modbus_tcp

4. 종료:
   Ctrl+C

==============================================================================
*/