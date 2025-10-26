#include "XgtFenParser.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "nlohmann/json.hpp"

// 생성자
XgtFenParser::XgtFenParser(AssetManager& assetManager) 
    : m_assetManager(assetManager) {}

// 소멸자
XgtFenParser::~XgtFenParser() {}

// 프로토콜 이름 반환
std::string XgtFenParser::getName() const {
    return "xgt-fen";
}

// 프로토콜 식별 (참고: 실제 식별은 PacketParser에서 포트 기반으로 수행되어야 함)
bool XgtFenParser::isProtocol(const u_char* payload, int size) const {
    // XGT FEN 프로토콜은 일반적으로 TCP 2004 포트를 사용합니다.
    // 이 함수는 PacketParser가 포트로 식별한 후 호출되므로, 
    // 여기서는 최소 페이로드 크기만 확인하거나, 알려진 시그니처를 확인할 수 있습니다.
    // 여기서는 단순화를 위해 true를 반환합니다.
    return size > 0;
}

// CSV 헤더 작성
void XgtFenParser::writeCsvHeader(std::ofstream& csv_stream) {
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,prid,dir,d,translated_addr,description\n";
}

// 패킷 파싱
void XgtFenParser::parse(const PacketInfo& info) {
    if (info.payload_size < 20) { // XGT FEN 헤더는 보통 20바이트
        return;
    }

    // 1. pdu.var.nm 추출 (휴리스틱)
    // 페이로드에서 '%'로 시작하고 ASCII 문자로 구성된 첫 번째 문자열을 찾습니다.
    std::string pduVarNm;
    for (int i = 0; i < info.payload_size; ++i) {
        if (info.payload[i] == '%') {
            const char* start = reinterpret_cast<const char*>(info.payload + i);
            // 문자열의 끝을 찾습니다 (널 종료 또는 비-ASCII 문자).
            for (int j = 0; i + j < info.payload_size; ++j) {
                char c = start[j];
                if (c == '\0' || !isprint(c)) {
                    pduVarNm = std::string(start, j);
                    break;
                }
            }
            if (!pduVarNm.empty()) break;
        }
    }

    if (pduVarNm.empty()) {
        return; // 유효한 변수명을 찾지 못함
    }

    // 2. 주소 변환 및 Description 조회
    std::string translatedAddr = m_assetManager.translateXgtAddress(pduVarNm);
    std::string description = m_assetManager.getDescription(translatedAddr);

    // 3. 출력
    // JSON (d 컬럼) 생성
    nlohmann::json details_json;
    details_json["pdu.var.nm"] = pduVarNm;
    std::string details_str = details_json.dump();

    // prid (Transaction ID)는 헤더의 특정 위치에 있을 수 있습니다. 여기서는 0으로 가정합니다.
    uint16_t prid = 0; 
    std::string direction = "request"; // 또는 response, 헤더 필드에 따라 결정

    // JSONL 라인 작성
    writeJsonl(info, direction, details_str);

    // CSV 라인 작성
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << prid << ","
                      << direction << ","
                      << escape_csv(details_str) << ","
                      << escape_csv(translatedAddr) << ","
                      << escape_csv(description) << "\n";
    }
}