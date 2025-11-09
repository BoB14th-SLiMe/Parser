#ifndef ELASTICSEARCH_CLIENT_H
#define ELASTICSEARCH_CLIENT_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct ElasticsearchConfig {
    std::string host = "localhost";
    int port = 9200;
    std::string username = "";
    std::string password = "";
    std::string index_prefix = "ics-packets";
    int bulk_size = 100;
    int flush_interval_ms = 5000;
    bool use_https = false;
};

class ElasticsearchClient {
public:
    explicit ElasticsearchClient(const ElasticsearchConfig& config);
    ~ElasticsearchClient();
    
    bool connect();
    void disconnect();
    bool isConnected() const { return m_connected; }
    
    // 단일 문서 전송
    bool indexDocument(const std::string& index, const json& document);
    
    // 벌크 전송 (성능 최적화)
    bool addToBulk(const std::string& protocol, const json& document);
    bool flushBulk();
    
    // 인덱스 관리
    bool createIndex(const std::string& index);
    bool deleteIndex(const std::string& index);
    
    // 시간 기반 인덱스 생성 (YYYY.MM.DD 형식)
    std::string getTimeBasedIndex(const std::string& protocol);

private:
    ElasticsearchConfig m_config;
    CURL* m_curl;
    bool m_connected;
    
    // 벌크 버퍼
    std::vector<std::string> m_bulk_buffer;
    std::mutex m_bulk_mutex;
    std::thread m_flush_thread;
    std::atomic<bool> m_stop_flush;
    
    // 내부 함수
    void autoFlushLoop();
    std::string buildUrl(const std::string& path);
    bool sendRequest(const std::string& url, const std::string& method, 
                     const std::string& data, std::string& response);
    
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
};

#endif // ELASTICSEARCH_CLIENT_H