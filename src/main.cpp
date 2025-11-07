#include <iostream>
#include <csignal>
#include <atomic>
#include "./PacketParser.h"

#ifdef _WIN32
#include <winsock2.h>

class WinSockInit {
public:
    WinSockInit() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed." << std::endl;
            exit(1);
        }
    }
    ~WinSockInit() {
        WSACleanup();
    }
};
#endif

// 전역 변수로 PacketParser 관리 (시그널 핸들러용)
static std::atomic<bool> g_running(true);
static PacketParser* g_parser = nullptr;

void signal_handler(int signum) {
    std::cout << "\n[INFO] Received signal " << signum << ", shutting down gracefully..." << std::endl;
    g_running = false;
    if (g_parser) {
        g_parser->stopCapture();
    }
}

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " <interface> [options]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Arguments:" << std::endl;
    std::cerr << "  interface          : Network interface to capture (e.g., eth0, ens33)" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Options:" << std::endl;
    std::cerr << "  --filter <bpf>     : BPF filter (default: none)" << std::endl;
    std::cerr << "  --rolling <min>    : Rolling interval in minutes (default: 30)" << std::endl;
    std::cerr << "  --threads <num>    : Number of worker threads (default: auto)" << std::endl;
    std::cerr << "  --no-redis         : Disable Redis" << std::endl;
    std::cerr << "  --no-es            : Disable Elasticsearch" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Examples:" << std::endl;
    std::cerr << "  " << program_name << " eth0" << std::endl;
    std::cerr << "  " << program_name << " eth0 --filter \"tcp port 502\"" << std::endl;
    std::cerr << "  " << program_name << " eth0 --rolling 15 --threads 4" << std::endl;
}

void list_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }
    
    std::cout << "\nAvailable network interfaces:" << std::endl;
    std::cout << "-----------------------------" << std::endl;
    
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << "  " << d->name;
        if (d->description) {
            std::cout << " (" << d->description << ")";
        }
        std::cout << std::endl;
        
        // IP 주소 출력
        for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((struct sockaddr_in*)a->addr)->sin_addr, ip, sizeof(ip));
                std::cout << "    IP: " << ip << std::endl;
            }
        }
    }
    std::cout << std::endl;
    
    pcap_freealldevs(alldevs);
}

int main(int argc, char* argv[]) {
    #ifdef _WIN32
        WinSockInit winSockInit;
    #endif

    // 시그널 핸들러 등록
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (argc < 2) {
        print_usage(argv[0]);
        list_interfaces();
        return 1;
    }

    // 설정 파싱
    CaptureConfig config;
    config.interface = argv[1];
    config.filter = "";
    config.rolling_interval_minutes = 0;
    config.num_threads = 0;
    config.enable_redis = true;
    config.enable_elasticsearch = true;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--filter" && i + 1 < argc) {
            config.filter = argv[++i];
        } else if (arg == "--rolling" && i + 1 < argc) {
            config.rolling_interval_minutes = std::atoi(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            config.num_threads = std::atoi(argv[++i]);
        } else if (arg == "--no-redis") {
            config.enable_redis = false;
        } else if (arg == "--no-es") {
            config.enable_elasticsearch = false;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            return 1;
        }
    }

    std::cout << "========================================" << std::endl;
    std::cout << "Real-time ICS Packet Capture & Analysis" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Interface: " << config.interface << std::endl;
    std::cout << "BPF Filter: " << (config.filter.empty() ? "none" : config.filter) << std::endl;
    std::cout << "Rolling Interval: " << config.rolling_interval_minutes << " minutes" << std::endl;
    std::cout << "Redis: " << (config.enable_redis ? "enabled" : "disabled") << std::endl;
    std::cout << "Elasticsearch: " << (config.enable_elasticsearch ? "enabled" : "disabled") << std::endl;
    std::cout << "========================================" << std::endl;

    // PacketParser 생성
    PacketParser parser(config);
    g_parser = &parser;

    // 캡처 시작
    if (!parser.startCapture()) {
        std::cerr << "[ERROR] Failed to start capture" << std::endl;
        return 2;
    }

    // 통계 출력 스레드
    std::thread stats_thread([&parser]() {
        while (g_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            
            auto stats = parser.getStatistics();
            std::cout << "\r[STATS] Captured: " << stats.packets_captured
                      << " | Processed: " << stats.packets_processed
                      << " | Redis: " << stats.redis_sent
                      << " | ES: " << stats.elasticsearch_sent
                      << " | Errors: " << stats.errors
                      << "          " << std::flush;
        }
    });

    // 캡처가 실행 중인 동안 대기
    while (g_running.load() && parser.isCapturing()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 정리
    if (stats_thread.joinable()) {
        stats_thread.join();
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "Capture session ended" << std::endl;
    
    auto final_stats = parser.getStatistics();
    std::cout << "Final Statistics:" << std::endl;
    std::cout << "  Packets Captured: " << final_stats.packets_captured << std::endl;
    std::cout << "  Packets Processed: " << final_stats.packets_processed << std::endl;
    std::cout << "  Sent to Redis: " << final_stats.redis_sent << std::endl;
    std::cout << "  Sent to Elasticsearch: " << final_stats.elasticsearch_sent << std::endl;
    std::cout << "  Errors: " << final_stats.errors << std::endl;
    std::cout << "========================================" << std::endl;

    g_parser = nullptr;
    return 0;
}