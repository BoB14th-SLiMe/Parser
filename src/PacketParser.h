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

// 패킷 데이터를 저장하는 구조체
struct PacketData {
    struct pcap_pkthdr header;
    std::vector<u_char> packet;
    
    PacketData(const struct pcap_pkthdr* h, const u_char* p) 
        : header(*h), packet(p, p + h->caplen) {}
};

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/", int time_interval = 30, int num_threads = 0);
    ~PacketParser();
    
    void parse(const struct pcap_pkthdr* header, const u_char* packet);
    void generateUnifiedOutput();
    
    // 멀티스레딩 제어
    void startWorkers();
    void stopWorkers();
    void waitForCompletion();

private:
    std::string m_output_dir;
    int m_time_interval;
    int m_num_threads;
    
    AssetManager m_assetManager;
    std::unique_ptr<UnifiedWriter> m_unified_writer;

    // 워커별 파서 (각 스레드가 독립적인 파서 인스턴스 사용)
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
    
    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
};

#endif // PACKET_PARSER_H