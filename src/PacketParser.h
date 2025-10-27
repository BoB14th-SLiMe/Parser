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
#ifndef _WIN32
#include <sys/time.h>
#endif
#include "./protocols/IProtocolParser.h"
#include "./protocols/ArpParser.h"
#include "./protocols/TcpSessionParser.h"
#include "AssetManager.h"
#include "TimeBasedCsvWriter.h"

// JSONL과 CSV 파일 스트림을 함께 관리하기 위한 구조체
struct FileStreams {
    std::ofstream jsonl_stream;
    std::ofstream csv_stream;
    std::mutex mutex; // 스레드 안전성을 위한 뮤텍스
    
    // 기본 생성자
    FileStreams() = default;
    
    // 이동 생성자
    FileStreams(FileStreams&& other) noexcept
        : jsonl_stream(std::move(other.jsonl_stream)),
          csv_stream(std::move(other.csv_stream)) {
        // mutex는 이동할 수 없으므로 새로 생성됨
    }
    
    // 이동 대입 연산자
    FileStreams& operator=(FileStreams&& other) noexcept {
        if (this != &other) {
            jsonl_stream = std::move(other.jsonl_stream);
            csv_stream = std::move(other.csv_stream);
            // mutex는 이동할 수 없으므로 그대로 유지
        }
        return *this;
    }
    
    // 복사 생성자와 복사 대입 연산자는 삭제
    FileStreams(const FileStreams&) = delete;
    FileStreams& operator=(const FileStreams&) = delete;
};

// 패킷 데이터를 저장하는 구조체
struct PacketData {
    struct pcap_pkthdr header;
    std::vector<u_char> packet;
    
    PacketData(const struct pcap_pkthdr* h, const u_char* p) 
        : header(*h), packet(p, p + h->caplen) {}
};

class PacketParser {
public:
    PacketParser(const std::string& output_dir = "output/", int time_interval = 0, int num_threads = 0);
    ~PacketParser();
    
    void parse(const struct pcap_pkthdr* header, const u_char* packet);
    void generateUnifiedCsv();
    
    // 멀티스레딩 제어
    void startWorkers();
    void stopWorkers();
    void waitForCompletion();

private:
    std::string m_output_dir;
    int m_time_interval;
    int m_num_threads;
    std::map<std::string, FileStreams> m_output_streams;
    
    AssetManager m_assetManager;
    std::unique_ptr<TimeBasedCsvWriter> m_time_writer;

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
    
    std::map<std::string, struct timeval> m_flow_start_times;

    void workerThread(int worker_id);
    void parsePacket(const struct pcap_pkthdr* header, const u_char* packet, int worker_id);
    void createParsersForWorker(int worker_id);
    
    std::string get_canonical_flow_id(const std::string& ip1, uint16_t port1, const std::string& ip2, uint16_t port2);
    void initialize_output_streams(const std::string& protocol);
    
    std::string escape_csv(const std::string& s);
};

#endif // PACKET_PARSER_H