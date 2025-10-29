#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <map>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <chrono>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include "./protocols/IProtocolParser.h"
#include "AssetManager.h"
#include "RedisCache.h"
#include "ElasticsearchClient.h"

// JSONL 파일 스트림 관리 (CSV 제거)
struct FileStreams {
    std::ofstream jsonl_stream;
    std::mutex mutex;
    
    FileStreams() = default;
    FileStreams(FileStreams&& other) noexcept
        : jsonl_stream(std::move(other.jsonl_stream)) {}
    
    FileStreams& operator=(FileStreams&& other) noexcept {
        if (this != &other) {
            jsonl_stream = std::move(other.jsonl_stream);
        }
        return *this;
    }
    
    FileStreams(const FileStreams&) = delete;
    FileStreams& operator=(const FileStreams&) = delete;
};

// 패킷 데이터 저장 구조체
struct PacketData {
    struct pcap_pkthdr header;
    std::vector<u_char> packet;
    
    PacketData(const struct pcap_pkthdr* h, const u_char* p) 
        : header(*h), packet(p, p + h->caplen) {}
};

// 실시간 캡처 설정
struct CaptureConfig {
    std::string interface;
    std::string filter;
    int snaplen = 65535;
    int rolling_interval_minutes = 30;
    bool enable_redis = true;
    bool enable_elasticsearch = true;
    int num_threads = 0;
};

class PacketParser {
public:
    explicit PacketParser(const CaptureConfig& config);
    ~PacketParser();
    
    // 실시간 캡처 시작/종료
    bool startCapture();
    void stopCapture();
    bool isCapturing() const { return m_capturing.load(); }
    
    // 패킷 처리 (콜백용)
    void parse(const struct pcap_pkthdr* header, const u_char* packet);
    
    // 통계
    struct Statistics {
        uint64_t packets_captured;
        uint64_t packets_processed;
        uint64_t redis_sent;
        uint64_t elasticsearch_sent;
        uint64_t errors;
    };
    Statistics getStatistics() const;

private:
    CaptureConfig m_config;
    std::string m_output_dir;
    int m_num_threads;
    
    // 출력 스트림 (JSONL만)
    std::map<std::string, FileStreams> m_output_streams;
    
    // 외부 시스템
    AssetManager m_assetManager;
    std::unique_ptr<RedisCache> m_redis_cache;
    std::unique_ptr<ElasticsearchClient> m_elasticsearch;
    
    // 워커별 파서
    std::vector<std::vector<std::unique_ptr<IProtocolParser>>> m_worker_parsers;
    
    // 멀티스레딩
    std::vector<std::thread> m_workers;
    std::queue<std::shared_ptr<PacketData>> m_packet_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    std::atomic<bool> m_stop_flag;
    std::atomic<bool> m_capturing;
    
    // 통계
    std::atomic<uint64_t> m_packets_captured;
    std::atomic<uint64_t> m_packets_processed;
    std::atomic<uint64_t> m_redis_sent;
    std::atomic<uint64_t> m_elasticsearch_sent;
    std::atomic<uint64_t> m_errors;
    
    // PCAP 핸들
    pcap_t* m_pcap_handle;
    std::thread m_capture_thread;
    
    // 30분 롤링 관리
    std::chrono::steady_clock::time_point m_session_start;
    std::thread m_rolling_thread;
    
    // 내부 함수
    void captureLoop();
    void rollingManager();
    void workerThread(int worker_id);
    void parsePacket(const struct pcap_pkthdr* header, const u_char* packet, int worker_id);
    void createParsersForWorker(int worker_id);
    
    void rotateOutputFiles();
    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, 
                                     const std::string& ip2, uint16_t port2);
    void initialize_output_streams(const std::string& protocol);
    
    void startWorkers();
    void stopWorkers();
    void waitForCompletion();
};

#endif // PACKET_PARSER_H