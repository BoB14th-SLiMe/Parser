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
    std::string host = "192.168.4.140";
    int port = 9200;
    std::string username = "";
    std::string password = "";
    std::string index_prefix = "ics-packets";
    int bulk_size = 100;  // 50 → 100으로 증가
    int flush_interval_ms = 1000;
    bool use_https = false;
};

class ElasticsearchClient {
public:
    explicit ElasticsearchClient(const ElasticsearchConfig& config);
    ~ElasticsearchClient();
    
    bool connect();
    void disconnect();
    bool isConnected() const { return m_connected; }
    
    bool indexDocument(const std::string& index, const json& document);
    bool addToBulk(const std::string& protocol, const json& document);
    bool flushBulk();
    
    bool createIndex(const std::string& index);
    bool deleteIndex(const std::string& index);
    
    std::string getTimeBasedIndex(const std::string& protocol);

private:
    ElasticsearchConfig m_config;
    std::atomic<bool> m_connected;
    
    // 벌크 버퍼
    std::vector<std::string> m_bulk_buffer;
    std::mutex m_bulk_mutex;
    std::thread m_flush_thread;
    std::atomic<bool> m_stop_flush;
    
    // ★ CURL 멀티스레딩 보호
    std::mutex m_curl_mutex;
    
    // 내부 함수
    void autoFlushLoop();
    std::string buildUrl(const std::string& path);
    bool sendRequest(const std::string& url, const std::string& method, 
                     const std::string& data, std::string& response);
    bool flushBulkInternal(const std::vector<std::string>& buffer);
    
    // ★ CURL 핸들을 함수 내부에서 생성/해제
    CURL* createCurlHandle();
    void destroyCurlHandle(CURL* curl);
    
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
};

#endif // ELASTICSEARCH_CLIENT_H