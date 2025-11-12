#include "ElasticsearchClient.h"
#include <iostream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <chrono>

ElasticsearchClient::ElasticsearchClient(const ElasticsearchConfig& config)
    : m_config(config), m_connected(false), m_stop_flush(false) {
    
    curl_global_init(CURL_GLOBAL_ALL);

    // 실시간 모드를 위한 기본값 조정
    if (m_config.bulk_size == 0 || m_config.bulk_size > 100) {
        m_config.bulk_size = 100;
    }
    if (m_config.flush_interval_ms == 0 || m_config.flush_interval_ms > 1000) {
        m_config.flush_interval_ms = 1000;
    }

    std::cout << "[Elasticsearch] Configured: bulk_size=" << m_config.bulk_size
              << ", flush_interval=" << m_config.flush_interval_ms << "ms" << std::endl;
}

ElasticsearchClient::~ElasticsearchClient() {
    disconnect();
    curl_global_cleanup();
}

CURL* ElasticsearchClient::createCurlHandle() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "[Elasticsearch] Failed to create CURL handle" << std::endl;
        return nullptr;
    }
    
    // 타임아웃 설정
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    
    // SSL 검증 비활성화 (필요시)
    if (m_config.use_https) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    
    return curl;
}

void ElasticsearchClient::destroyCurlHandle(CURL* curl) {
    if (curl) {
        curl_easy_cleanup(curl);
    }
}

bool ElasticsearchClient::connect() {
    // 연결 테스트용 CURL 생성
    CURL* test_curl = createCurlHandle();
    if (!test_curl) {
        std::cerr << "[Elasticsearch] Failed to initialize CURL" << std::endl;
        return false;
    }
    
    // 연결 테스트
    std::string response;
    curl_easy_setopt(test_curl, CURLOPT_URL, buildUrl("").c_str());
    curl_easy_setopt(test_curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(test_curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode res = curl_easy_perform(test_curl);
    destroyCurlHandle(test_curl);
    
    if (res != CURLE_OK) {
        std::cerr << "[Elasticsearch] Connection test failed: " 
                  << curl_easy_strerror(res) << std::endl;
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
    // ★ 함수 내부에서 CURL 생성 (스레드 안전)
    std::lock_guard<std::mutex> lock(m_curl_mutex);
    
    CURL* curl = createCurlHandle();
    if (!curl) {
        std::cerr << "[Elasticsearch] Failed to create CURL handle" << std::endl;
        return false;
    }
    
    // 최대 3회 재시도
    int max_retries = 3;
    bool success = false;
    
    for (int retry = 0; retry < max_retries; ++retry) {
        response.clear();
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        if (!m_config.username.empty()) {
            std::string auth = m_config.username + ":" + m_config.password;
            curl_easy_setopt(curl, CURLOPT_USERPWD, auth.c_str());
        }
        
        if (method == "POST" || method == "PUT") {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            if (method == "PUT") {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
            }
        } else if (method == "DELETE") {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        }
        
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        
        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code >= 200 && http_code < 300) {
                success = true;
                break;
            }
        }
        
        // 재시도 전 대기
        if (retry < max_retries - 1) {
            std::cerr << "[Elasticsearch] Request failed (retry " << retry + 1 
                      << "/" << max_retries << "): " << curl_easy_strerror(res) << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    destroyCurlHandle(curl);
    
    if (!success) {
        std::cerr << "[Elasticsearch] Request failed after " << max_retries << " retries" << std::endl;
    }
    
    return success;
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

bool ElasticsearchClient::addToBulk(const std::string& protocol, const json& document) {
    if (!m_connected) return false;
    
    std::lock_guard<std::mutex> lock(m_bulk_mutex);

    std::string index = getTimeBasedIndex(protocol);

    json action = {
        {"index", {
            {"_index", index}
        }}
    };

    m_bulk_buffer.push_back(action.dump());
    m_bulk_buffer.push_back(document.dump());

    // 버퍼가 설정된 사이즈에 도달하면 즉시 전송
    if (m_bulk_buffer.size() >= static_cast<size_t>(m_config.bulk_size * 2)) {
        // ★ 잠금을 해제하고 flush 호출 (데드락 방지)
        std::vector<std::string> buffer_copy = m_bulk_buffer;
        m_bulk_buffer.clear();

        // unlock은 자동으로 됨 (lock_guard scope 벗어남)
        return flushBulkInternal(buffer_copy);
    }

    return true;
}

bool ElasticsearchClient::flushBulkInternal(const std::vector<std::string>& buffer) {
    if (buffer.empty()) return true;
    if (!m_connected) {
        std::cerr << "[Elasticsearch] Not connected, cannot flush" << std::endl;
        return false;
    }

    size_t doc_count = buffer.size() / 2;

    // NDJSON 형식으로 결합
    std::stringstream bulk_data;
    for (const auto& line : buffer) {
        bulk_data << line << "\n";
    }

    std::string url = buildUrl("_bulk");
    std::string response;
    bool success = sendRequest(url, "POST", bulk_data.str(), response);

    if (success) {
        // 성공 시에도 주기적으로 로그 출력 (1000개 단위)
        static std::atomic<size_t> es_total_docs{0};
        size_t total = es_total_docs.fetch_add(doc_count) + doc_count;
        if (total % 1000 < doc_count || doc_count >= 1000) {
            std::cout << "[Elasticsearch] ✓ Sent " << total << " documents" << std::endl;
        }
    } else {
        std::cerr << "[Elasticsearch] ✗ Bulk flush failed for " << doc_count << " documents" << std::endl;
    }

    return success;
}

bool ElasticsearchClient::flushBulk() {
    std::lock_guard<std::mutex> lock(m_bulk_mutex);

    if (m_bulk_buffer.empty()) return true;

    std::vector<std::string> buffer_copy = m_bulk_buffer;
    m_bulk_buffer.clear();
    
    return flushBulkInternal(buffer_copy);
}

void ElasticsearchClient::autoFlushLoop() {
    std::cout << "[Elasticsearch] Auto-flush thread started (interval: "
              << m_config.flush_interval_ms << "ms)" << std::endl;

    while (!m_stop_flush.load()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(m_config.flush_interval_ms)
        );

        // 버퍼에 데이터가 있으면 무조건 flush
        {
            std::lock_guard<std::mutex> lock(m_bulk_mutex);
            if (!m_bulk_buffer.empty()) {
                std::vector<std::string> buffer_copy = m_bulk_buffer;
                m_bulk_buffer.clear();

                flushBulkInternal(buffer_copy);
            }
        }
    }

    std::cout << "[Elasticsearch] Auto-flush thread stopped" << std::endl;
}

bool ElasticsearchClient::createIndex(const std::string& index) {
    if (!m_connected) return false;
    
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