#include "ElasticsearchClient.h"
#include <iostream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <chrono>

ElasticsearchClient::ElasticsearchClient(const ElasticsearchConfig& config)
    : m_config(config), m_curl(nullptr), m_connected(false), m_stop_flush(false) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

ElasticsearchClient::~ElasticsearchClient() {
    disconnect();
    curl_global_cleanup();
}

bool ElasticsearchClient::connect() {
    m_curl = curl_easy_init();
    if (!m_curl) {
        std::cerr << "[Elasticsearch] Failed to initialize CURL" << std::endl;
        return false;
    }
    
    // 연결 테스트
    std::string response;
    if (!sendRequest(buildUrl(""), "GET", "", response)) {
        std::cerr << "[Elasticsearch] Connection test failed" << std::endl;
        return false;
    }
    
    m_connected = true;
    std::cout << "[Elasticsearch] Connected to " << m_config.host 
              << ":" << m_config.port << std::endl;
    
    // 자동 플러시 스레드 시작
    m_stop_flush = false;
    m_flush_thread = std::thread(&ElasticsearchClient::autoFlushLoop, this);
    
    return true;
}

void ElasticsearchClient::disconnect() {
    m_stop_flush = true;
    if (m_flush_thread.joinable()) {
        m_flush_thread.join();
    }
    
    flushBulk(); // 남은 데이터 전송
    
    if (m_curl) {
        curl_easy_cleanup(m_curl);
        m_curl = nullptr;
    }
    m_connected = false;
}

std::string ElasticsearchClient::buildUrl(const std::string& path) {
    std::stringstream ss;
    ss << (m_config.use_https ? "https://" : "http://")
       << m_config.host << ":" << m_config.port;
    if (!path.empty()) {
        ss << "/" << path;
    }
    return ss.str();
}

size_t ElasticsearchClient::writeCallback(void* contents, size_t size, 
                                          size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool ElasticsearchClient::sendRequest(const std::string& url, 
                                       const std::string& method,
                                       const std::string& data, 
                                       std::string& response) {
    if (!m_curl) return false;
    
    curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, 10L);
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    if (!m_config.username.empty()) {
        std::string auth = m_config.username + ":" + m_config.password;
        curl_easy_setopt(m_curl, CURLOPT_USERPWD, auth.c_str());
    }
    
    if (method == "POST" || method == "PUT") {
        curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, data.c_str());
        if (method == "PUT") {
            curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, "PUT");
        }
    } else if (method == "DELETE") {
        curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }
    
    curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(m_curl);
    curl_slist_free_all(headers);
    
    if (res != CURLE_OK) {
        std::cerr << "[Elasticsearch] Request failed: " 
                  << curl_easy_strerror(res) << std::endl;
        return false;
    }
    
    long http_code = 0;
    curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    return (http_code >= 200 && http_code < 300);
}

std::string ElasticsearchClient::getTimeBasedIndex(const std::string& protocol) {
    auto now = std::time(nullptr);
    auto tm = *std::gmtime(&now);
    
    std::stringstream ss;
    ss << m_config.index_prefix << "-" << protocol << "-"
       << std::put_time(&tm, "%Y.%m.%d");
    return ss.str();
}

bool ElasticsearchClient::indexDocument(const std::string& index, 
                                         const json& document) {
    if (!m_connected) return false;
    
    std::string url = buildUrl(index + "/_doc");
    std::string response;
    
    return sendRequest(url, "POST", document.dump(), response);
}

bool ElasticsearchClient::addToBulk(const std::string& protocol, 
                                     const json& document) {
    std::lock_guard<std::mutex> lock(m_bulk_mutex);
    
    std::string index = getTimeBasedIndex(protocol);
    
    // Bulk API 형식: action_and_meta_data\n + optional_source\n
    json action = {
        {"index", {
            {"_index", index}
        }}
    };
    
    m_bulk_buffer.push_back(action.dump());
    m_bulk_buffer.push_back(document.dump());
    
    // 버퍼가 꽉 차면 즉시 전송
    if (m_bulk_buffer.size() >= static_cast<size_t>(m_config.bulk_size * 2)) {
        return flushBulk();
    }
    
    return true;
}

bool ElasticsearchClient::flushBulk() {
    std::lock_guard<std::mutex> lock(m_bulk_mutex);
    
    if (m_bulk_buffer.empty()) return true;
    if (!m_connected) return false;
    
    // NDJSON 형식으로 결합
    std::stringstream bulk_data;
    for (const auto& line : m_bulk_buffer) {
        bulk_data << line << "\n";
    }
    
    std::string url = buildUrl("_bulk");
    std::string response;
    bool success = sendRequest(url, "POST", bulk_data.str(), response);
    
    if (success) {
        std::cout << "[Elasticsearch] Flushed " << (m_bulk_buffer.size() / 2) 
                  << " documents" << std::endl;
        m_bulk_buffer.clear();
    } else {
        std::cerr << "[Elasticsearch] Bulk flush failed" << std::endl;
    }
    
    return success;
}

void ElasticsearchClient::autoFlushLoop() {
    while (!m_stop_flush.load()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(m_config.flush_interval_ms)
        );
        flushBulk();
    }
}

bool ElasticsearchClient::createIndex(const std::string& index) {
    if (!m_connected) return false;
    
    // ICS 패킷에 최적화된 매핑 정의
    json mapping = {
        {"mappings", {
            {"properties", {
                {"@timestamp", {{"type", "date"}}},
                {"protocol", {{"type", "keyword"}}},
                {"src_ip", {{"type", "ip"}}},
                {"dst_ip", {{"type", "ip"}}},
                {"src_port", {{"type", "integer"}}},
                {"dst_port", {{"type", "integer"}}},
                {"src_mac", {{"type", "keyword"}}},
                {"dst_mac", {{"type", "keyword"}}},
                {"direction", {{"type", "keyword"}}},
                {"src_asset", {{"type", "object"}}},
                {"dst_asset", {{"type", "object"}}},
                {"protocol_details", {{"type", "object"}}},
                {"features", {{"type", "object"}}}
            }}
        }}
    };
    
    std::string url = buildUrl(index);
    std::string response;
    
    return sendRequest(url, "PUT", mapping.dump(), response);
}

bool ElasticsearchClient::deleteIndex(const std::string& index) {
    if (!m_connected) return false;
    
    std::string url = buildUrl(index);
    std::string response;
    
    return sendRequest(url, "DELETE", "", response);
}