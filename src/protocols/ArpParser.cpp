#include "ArpParser.h"
#include "../network/network_headers.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <utility> // for std::pair
#include <tuple>   // --- tuple 헤더 추가 ---

// Helper Function to format timestamp to ISO 8601 (Cross-platform)
static std::string format_timestamp_arp(const struct timeval& ts) {
    char buf[sizeof "2011-10-08T07:07:09.000000Z"];
    char buft[sizeof "2011-10-08T07:07:09"];
    time_t sec = ts.tv_sec;
    struct tm gmt;

    // 플랫폼에 맞는 스레드 안전한 시간 변환 함수 사용
    #ifdef _WIN32
        gmtime_s(&gmt, &sec);
    #else
        gmtime_r(&sec, &gmt);
    #endif

    strftime(buft, sizeof buft, "%Y-%m-%dT%H:%M:%S", &gmt);
    // Windows에서는 ts.tv_usec가 long 타입일 수 있으므로 int로 캐스팅
    snprintf(buf, sizeof buf, "%.*s.%06dZ", (int)sizeof(buft) - 1, buft, (int)ts.tv_usec);
    return std::string(buf);
}

ArpParser::ArpParser() {}
ArpParser::~ArpParser() {}

std::string ArpParser::mac_to_string(const uint8_t* mac) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac[i]) << (i < 5 ? ":" : "");
    }
    return ss.str();
}

// --- 수정: 반환 타입을 std::tuple로 변경 (timestamp, json_details, op_code) ---
std::tuple<std::string, std::string, int> ArpParser::parse(const struct pcap_pkthdr* header, const u_char* arp_payload, int size) {
    if (size < sizeof(ARPHeader)) {
        return {"", "", 0}; // Return empty tuple on failure
    }

    const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(arp_payload);
    std::stringstream details_ss;

    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (void*)arp_header->spa, spa_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (void*)arp_header->tpa, tpa_str, INET_ADDRSTRLEN);

    uint16_t op_code = ntohs(arp_header->oper); // --- op_code 추출 ---

    details_ss << "{\"op\":" << op_code
               << ",\"smac\":\"" << mac_to_string(arp_header->sha) << "\""
               << ",\"sip\":\"" << spa_str << "\""
               << ",\"tmac\":\"" << mac_to_string(arp_header->tha) << "\""
               << ",\"tip\":\"" << tpa_str << "\"}";

    std::string timestamp_str = format_timestamp_arp(header->ts);
    
    // --- op_code를 함께 반환 ---
    return {timestamp_str, details_ss.str(), op_code};
}
