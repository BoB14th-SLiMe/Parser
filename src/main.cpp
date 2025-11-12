#include <iostream>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <chrono>
#include <thread>
#include <pcap.h>
#include "PacketParser.h"
#include "RedisCache.h"
#include "ElasticsearchClient.h"

// ============================================================================
// Global Variables
// ============================================================================
static volatile bool g_running = true;
static PacketParser* g_parser = nullptr;

// ============================================================================
// Signal Handler
// ============================================================================
void signalHandler(int signal) {
    std::cout << "\n[Main] Received signal " << signal << ", shutting down..." << std::endl;
    g_running = false;
}

// ============================================================================
// Helper Functions
// ============================================================================
std::string getEnv(const char* name, const std::string& default_value = "") {
    const char* value = std::getenv(name);
    return value ? std::string(value) : default_value;
}

int getEnvInt(const char* name, int default_value = 0) {
    const char* value = std::getenv(name);
    return value ? std::atoi(value) : default_value;
}

bool getEnvBool(const char* name, bool default_value = false) {
    const char* value = std::getenv(name);
    if (!value) return default_value;
    std::string str(value);
    return (str == "true" || str == "1" || str == "yes");
}

void printUsage(const char* program) {
    std::cout << "\nUsage: " << program << " [options]\n\n"
              << "Options:\n"
              << "  -i, --interface <name>    Network interface to capture (default: any)\n"
              << "  -p, --pcap <file>         PCAP file to read (offline mode)\n"
              << "  -f, --filter <bpf>        BPF filter string\n"
              << "  -o, --output <dir>        Output directory (default: /data/output)\n"
              << "  -r, --rolling <minutes>   File rolling interval in minutes (0 = no rolling)\n"
              << "  --realtime                Realtime mode (no file output, only ES/Redis)\n"
              << "  --threads <num>           Number of worker threads (0 = auto)\n"
              << "  -h, --help                Show this help message\n\n"
              << "Environment Variables:\n"
              << "  NETWORK_INTERFACE         Network interface (default: any)\n"
              << "  BPF_FILTER                BPF filter string\n"
              << "  OUTPUT_DIR                Output directory\n"
              << "  ROLLING_INTERVAL          Rolling interval in minutes\n"
              << "  PARSER_MODE               'realtime' or 'with-files'\n"
              << "  PARSER_THREADS            Number of worker threads\n"
              << "\n"
              << "  ELASTICSEARCH_HOST        Elasticsearch host (default: localhost)\n"
              << "  ELASTICSEARCH_PORT        Elasticsearch port (default: 9200)\n"
              << "  ELASTICSEARCH_USERNAME    Elasticsearch username\n"
              << "  ELASTICSEARCH_PASSWORD    Elasticsearch password\n"
              << "  ELASTICSEARCH_INDEX_PREFIX Index prefix (default: ics-packets)\n"
              << "  ELASTICSEARCH_USE_HTTPS   Use HTTPS (true/false, default: false)\n"
              << "  ES_BULK_SIZE              Bulk size (default: 100)\n"
              << "  ES_BULK_FLUSH_INTERVAL_MS Flush interval in ms (default: 100)\n"
              << "\n"
              << "  REDIS_HOST                Redis host (default: localhost)\n"
              << "  REDIS_PORT                Redis port (default: 6379)\n"
              << "  REDIS_PASSWORD            Redis password\n"
              << "  REDIS_DB                  Redis database number (default: 0)\n"
              << "  REDIS_POOL_SIZE           Connection pool size (default: 8)\n"
              << "  REDIS_ASYNC_WRITERS       Number of async writers (default: 2)\n"
              << "  REDIS_ASYNC_QUEUE_SIZE    Async queue size (default: 10000)\n"
              << "  REDIS_TIMEOUT_MS          Timeout in ms (default: 1000)\n"
              << std::endl;
}

// ============================================================================
// Packet Callback
// ============================================================================
void packetCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (!g_running) return;

    PacketParser* parser = reinterpret_cast<PacketParser*>(user);
    parser->parse(header, packet);
}

// ============================================================================
// Main Function
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "===   OT Security Monitoring System - Packet Parser   ===" << std::endl;
    std::cout << std::string(70, '=') << "\n" << std::endl;

    // 기본값 설정 (환경 변수 또는 기본값)
    std::string interface = getEnv("NETWORK_INTERFACE", "any");
    std::string bpf_filter = getEnv("BPF_FILTER", "");
    std::string output_dir = getEnv("OUTPUT_DIR", "/data/output");
    int rolling_interval = getEnvInt("ROLLING_INTERVAL", 0);
    std::string parser_mode = getEnv("PARSER_MODE", "with-files");
    bool realtime = (parser_mode == "realtime");
    int num_threads = getEnvInt("PARSER_THREADS", 0);
    std::string pcap_file = "";  // PCAP 파일 경로

    // 커맨드 라인 인자 파싱
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"pcap", required_argument, 0, 'p'},
        {"filter", required_argument, 0, 'f'},
        {"output", required_argument, 0, 'o'},
        {"rolling", required_argument, 0, 'r'},
        {"realtime", no_argument, 0, 1},
        {"threads", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "i:p:f:o:r:t:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                pcap_file = optarg;
                break;
            case 'f':
                bpf_filter = optarg;
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 'r':
                rolling_interval = std::atoi(optarg);
                break;
            case 1:
                realtime = true;
                break;
            case 't':
                num_threads = std::atoi(optarg);
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    // Signal handler 등록
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // ========================================================================
    // Elasticsearch 설정
    // ========================================================================
    ElasticsearchConfig es_config;
    es_config.host = getEnv("ELASTICSEARCH_HOST", "192.168.4.140");
    es_config.port = getEnvInt("ELASTICSEARCH_PORT", 9200);
    es_config.username = getEnv("ELASTICSEARCH_USERNAME", "");
    es_config.password = getEnv("ELASTICSEARCH_PASSWORD", "");
    es_config.index_prefix = getEnv("ELASTICSEARCH_INDEX_PREFIX", "ics-packets");
    es_config.use_https = getEnvBool("ELASTICSEARCH_USE_HTTPS", false);
    es_config.bulk_size = getEnvInt("ES_BULK_SIZE", 100);
    es_config.flush_interval_ms = getEnvInt("ES_BULK_FLUSH_INTERVAL_MS", 100);

    // ========================================================================
    // Redis 설정
    // ========================================================================
    RedisCacheConfig redis_config;
    redis_config.host = getEnv("REDIS_HOST", "localhost");
    redis_config.port = getEnvInt("REDIS_PORT", 6379);
    redis_config.password = getEnv("REDIS_PASSWORD", "");
    redis_config.db = getEnvInt("REDIS_DB", 0);
    redis_config.pool_size = getEnvInt("REDIS_POOL_SIZE", 8);
    redis_config.async_writers = getEnvInt("REDIS_ASYNC_WRITERS", 2);
    redis_config.async_queue_size = getEnvInt("REDIS_ASYNC_QUEUE_SIZE", 10000);
    redis_config.timeout_ms = getEnvInt("REDIS_TIMEOUT_MS", 1000);

    // ========================================================================
    // 설정 출력
    // ========================================================================
    std::cout << "[Config] Configuration:" << std::endl;
    if (!pcap_file.empty()) {
        std::cout << "  Input Mode: PCAP File" << std::endl;
        std::cout << "  PCAP File: " << pcap_file << std::endl;
    } else {
        std::cout << "  Input Mode: Live Capture" << std::endl;
        std::cout << "  Network Interface: " << interface << std::endl;
    }
    if (!bpf_filter.empty()) {
        std::cout << "  BPF Filter: " << bpf_filter << std::endl;
    }
    std::cout << "  Output Directory: " << output_dir << std::endl;
    std::cout << "  Rolling Interval: " << rolling_interval << " minutes" << std::endl;
    std::cout << "  Mode: " << (realtime ? "Realtime (no file output)" : "With file output") << std::endl;
    std::cout << "  Worker Threads: " << (num_threads == 0 ? "Auto" : std::to_string(num_threads)) << std::endl;
    std::cout << std::endl;

    // 파일 출력 모드일 때는 Elasticsearch/Redis 비활성화
    RedisCacheConfig* redis_config_ptr = nullptr;
    ElasticsearchConfig* es_config_ptr = nullptr;

    if (realtime) {
        // Realtime 모드: Elasticsearch와 Redis 사용
        std::cout << "[Config] Elasticsearch:" << std::endl;
        std::cout << "  Host: " << es_config.host << ":" << es_config.port << std::endl;
        std::cout << "  Index Prefix: " << es_config.index_prefix << std::endl;
        std::cout << "  HTTPS: " << (es_config.use_https ? "Yes" : "No") << std::endl;
        std::cout << "  Bulk Size: " << es_config.bulk_size << std::endl;
        std::cout << "  Flush Interval: " << es_config.flush_interval_ms << " ms" << std::endl;
        std::cout << std::endl;

        std::cout << "[Config] Redis:" << std::endl;
        std::cout << "  Host: " << redis_config.host << ":" << redis_config.port << std::endl;
        std::cout << "  Database: " << redis_config.db << std::endl;
        std::cout << "  Pool Size: " << redis_config.pool_size << std::endl;
        std::cout << "  Async Writers: " << redis_config.async_writers << std::endl;
        std::cout << std::endl;

        redis_config_ptr = &redis_config;
        es_config_ptr = &es_config;
    } else {
        // 파일 출력 모드: Elasticsearch와 Redis 비활성화
        std::cout << "[Config] Elasticsearch: Disabled (file output mode)" << std::endl;
        std::cout << "[Config] Redis: Disabled (file output mode)" << std::endl;
        std::cout << std::endl;
    }

    // ========================================================================
    // PacketParser 초기화
    // ========================================================================
    std::cout << "[Init] Initializing PacketParser..." << std::endl;
    g_parser = new PacketParser(
        output_dir,
        rolling_interval,
        num_threads,
        redis_config_ptr,
        es_config_ptr,
        realtime  // disable_file_output
    );

    // ========================================================================
    // Worker 스레드 시작
    // ========================================================================
    std::cout << "[Init] Starting worker threads..." << std::endl;
    g_parser->startWorkers();

    // ========================================================================
    // pcap 초기화
    // ========================================================================
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (!pcap_file.empty()) {
        // PCAP 파일 모드
        std::cout << "[PCAP] Opening PCAP file: " << pcap_file << std::endl;
        handle = pcap_open_offline(pcap_file.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << "[ERROR] Could not open PCAP file " << pcap_file << ": " << errbuf << std::endl;
            delete g_parser;
            return 1;
        }
    } else {
        // 라이브 캡처 모드
        std::cout << "[PCAP] Opening interface: " << interface << std::endl;
        handle = pcap_open_live(interface.c_str(), 65535, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "[ERROR] Could not open device " << interface << ": " << errbuf << std::endl;
            delete g_parser;
            return 1;
        }
    }

    // BPF 필터 설정
    if (!bpf_filter.empty()) {
        struct bpf_program fp;
        bpf_u_int32 net = 0;

        std::cout << "[PCAP] Compiling BPF filter: " << bpf_filter << std::endl;
        if (pcap_compile(handle, &fp, bpf_filter.c_str(), 0, net) == -1) {
            std::cerr << "[ERROR] Could not compile filter: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            delete g_parser;
            return 1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "[ERROR] Could not set filter: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            delete g_parser;
            return 1;
        }

        pcap_freecode(&fp);
        std::cout << "[PCAP] BPF filter applied successfully" << std::endl;
    }

    // ========================================================================
    // 패킷 캡처 시작
    // ========================================================================
    std::cout << "\n" << std::string(70, '=') << std::endl;
    if (!pcap_file.empty()) {
        std::cout << "===  Processing PCAP file. Press Ctrl+C to stop...   ===" << std::endl;
    } else {
        std::cout << "===  Packet capture started. Press Ctrl+C to stop...  ===" << std::endl;
    }
    std::cout << std::string(70, '=') << "\n" << std::endl;

    int packet_count = 0;
    auto last_stats = std::chrono::steady_clock::now();

    if (!pcap_file.empty()) {
        // PCAP 파일 모드: 블로킹 방식으로 모든 패킷 처리
        std::cout << "[PCAP] Reading packets from file..." << std::endl;
        int result = pcap_loop(handle, 0, packetCallback, reinterpret_cast<u_char*>(g_parser));

        if (result == -1) {
            std::cerr << "[ERROR] pcap_loop error: " << pcap_geterr(handle) << std::endl;
        } else if (result == -2) {
            std::cout << "[PCAP] File processing interrupted by user" << std::endl;
        } else {
            std::cout << "[PCAP] File reading completed" << std::endl;
        }

        // PCAP 파일 모드: 큐에 있는 모든 패킷이 처리될 때까지 대기
        std::cout << "[PCAP] Waiting for all packets to be processed..." << std::endl;
        g_parser->waitForCompletion();
        std::cout << "[PCAP] All packets processed successfully" << std::endl;
    } else {
        // 라이브 캡처 모드: non-blocking 방식
        pcap_setnonblock(handle, 1, errbuf);

        while (g_running) {
            int result = pcap_dispatch(handle, 100, packetCallback, reinterpret_cast<u_char*>(g_parser));

            if (result == -1) {
                std::cerr << "[ERROR] pcap_dispatch error: " << pcap_geterr(handle) << std::endl;
                break;
            } else if (result == 0) {
                // No packets, sleep briefly
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            } else {
                packet_count += result;
            }

            // 통계 출력 (30초마다)
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_stats).count() >= 30) {
                std::cout << "[Stats] Packets captured: " << packet_count << std::endl;

                // Redis 통계
                if (g_parser->getRedisCache() && g_parser->getRedisCache()->isConnected()) {
                    g_parser->getRedisCache()->printStats();
                }

                packet_count = 0;
                last_stats = now;
            }
        }
    }

    // ========================================================================
    // 종료 처리
    // ========================================================================
    std::cout << "\n[Main] Shutting down..." << std::endl;

    // pcap 종료
    pcap_close(handle);
    std::cout << "[PCAP] Closed" << std::endl;

    // Worker 종료
    std::cout << "[Main] Stopping workers..." << std::endl;
    // PCAP 파일 모드에서는 이미 waitForCompletion()을 호출했으므로 바로 stopWorkers() 호출
    if (pcap_file.empty()) {
        // 라이브 캡처 모드에서만 waitForCompletion() 호출
        g_parser->waitForCompletion();
    }
    g_parser->stopWorkers();

    // 최종 flush
    if (!realtime) {
        std::cout << "[Main] Generating final output..." << std::endl;
        g_parser->generateUnifiedOutput();
    }

    // 최종 통계
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "===                   Final Statistics                    ===" << std::endl;
    std::cout << std::string(70, '=') << std::endl;

    if (g_parser->getRedisCache() && g_parser->getRedisCache()->isConnected()) {
        g_parser->getRedisCache()->printStats();
    }

    // Cleanup
    delete g_parser;
    g_parser = nullptr;

    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "===               Shutdown complete. Goodbye!             ===" << std::endl;
    std::cout << std::string(70, '=') << "\n" << std::endl;

    return 0;
}
