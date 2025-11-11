#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#ifndef _WIN32
#include <sys/time.h>
#endif
#include "./protocols/IProtocolParser.h"
#include "AssetManager.h"
#include "UnifiedWriter.h"
#include "RedisCache.h"
#include "ElasticsearchClient.h"

// 패킷 데이터를 저장하는 구조체
struct PacketData {
    struct pcap_pkthdr header;
    std::vector<u_char> packet;
    
    PacketData(const struct pcap_pkthdr* h, const u_char* p) 
        : header(*h), packet(p, p + h->caplen) {}
};

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/", 
                 int time_interval = 0, 
                 int num_threads = 0,
                 const RedisCacheConfig* redis_config = nullptr,
                 const ElasticsearchConfig* es_config = nullptr,
                 bool disable_file_output = false);
    ~PacketParser();
    
    void parse(const struct pcap_pkthdr* header, const u_char* packet);
    void generateUnifiedOutput();
    
    // 멀티스레딩 제어
    void startWorkers();
    void stopWorkers();
    void waitForCompletion();
    
    // Redis/Elasticsearch 접근자
    RedisCache* getRedisCache() { return m_redis_cache.get(); }
    ElasticsearchClient* getElasticsearch() { return m_elasticsearch.get(); }

private:
    std::string m_output_dir;
    int m_time_interval;
    int m_num_threads;
    bool m_disable_file_output;
    
    AssetManager m_assetManager;
    std::unique_ptr<UnifiedWriter> m_unified_writer;
    
    // Redis & Elasticsearch
    std::unique_ptr<RedisCache> m_redis_cache;
    std::unique_ptr<ElasticsearchClient> m_elasticsearch;
    
    // 멤버 순서 변경: 선언 순서와 초기화 순서를 일치시킴
    bool m_use_redis;
    bool m_use_elasticsearch;

    // 워커별 파서
    std::vector<std::vector<std::unique_ptr<IProtocolParser>>> m_worker_parsers;
    
    // 멀티스레딩 관련
    std::vector<std::thread> m_workers;
    std::queue<std::shared_ptr<PacketData>> m_packet_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    std::atomic<bool> m_stop_flag;
    std::atomic<size_t> m_packets_processed;
    std::atomic<size_t> m_packets_queued;

    void workerThread(int worker_id);
    void parsePacket(const struct pcap_pkthdr* header, const u_char* packet, int worker_id);
    void createParsersForWorker(int worker_id);
    void realtimeFlushThread();
    
    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    
    void sendToBackends(const UnifiedRecord& record);
};


#endif // PACKET_PARSER_H