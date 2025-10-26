#include "AssetManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>

// CSV 한 줄을 파싱하는 헬퍼 함수
std::vector<std::string> parseCsvRow(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream ss(line);
    std::string field;
    bool in_quotes = false;

    char c;
    while (ss.get(c)) {
        if (c == '\"') {
            in_quotes = !in_quotes;
        } else if (c == ',' && !in_quotes) {
            fields.push_back(field);
            field.clear();
        } else {
            field += c;
        }
    }
    fields.push_back(field); // 마지막 필드 추가
    return fields;
}

AssetManager::AssetManager(const std::string& ipCsvPath, 
                         const std::string& inputCsvPath, 
                         const std::string& outputCsvPath) {
    try {
        loadIpCsv(ipCsvPath);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not load IP CSV file '" << ipCsvPath << "'. " << e.what() << std::endl;
    }
    try {
        loadTagCsv(inputCsvPath);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not load Input Tag CSV file '" << inputCsvPath << "'. " << e.what() << std::endl;
    }
    try {
        loadTagCsv(outputCsvPath);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not load Output Tag CSV file '" << outputCsvPath << "'. " << e.what() << std::endl;
    }

    std::cout << "AssetManager initialized. Loaded " << ipDeviceMap.size() << " IP entries and " 
              << tagDescriptionMap.size() << " tag entries." << std::endl;
}

// 자산IP CSV 로드
void AssetManager::loadIpCsv(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file.");
    }

    std::string line;
    // 헤더 스킵 (필요시) - 이 파일은 헤더가 불규칙하므로 그냥 파싱 시도
    while (std::getline(file, line)) {
        std::vector<std::string> fields = parseCsvRow(line);

        // 유선 보안리빙랩 (F열, G열)
        if (fields.size() > 6) {
            std::string deviceName = fields[5];
            std::string ip = fields[6];
            if (!deviceName.empty() && !ip.empty() && ip.find('.') != std::string::npos) {
                ipDeviceMap[ip] = deviceName;
            }
        }
        // 무선 보안리빙랩 (B열, C열)
        if (fields.size() > 2) {
             std::string deviceName = fields[1];
             std::string ip = fields[2];
             if (!deviceName.empty() && !ip.empty() && ip.find('.') != std::string::npos) {
                ipDeviceMap[ip] = deviceName;
             }
        }
    }
}

// 유선_Input / 유선_Output CSV 로드
void AssetManager::loadTagCsv(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file.");
    }

    std::string line;
    std::getline(file, line); // 헤더 스킵

    std::set<int> tagColumns = {3, 4, 5, 6, 7}; // 미쯔비시, LS, SIEMENS, 탈부착(LS), 탈부착(미쯔비시)

    while (std::getline(file, line)) {
        std::vector<std::string> fields = parseCsvRow(line);
        if (fields.size() > 1) {
            std::string description = fields[1]; // '내용' 컬럼
            if (description.empty()) continue;

            for (int col : tagColumns) {
                if (col < fields.size()) {
                    std::string tag = fields[col];
                    if (!tag.empty()) {
                        tagDescriptionMap[tag] = description;
                    }
                }
            }
        }
    }
}

std::string AssetManager::getDeviceName(const std::string& ip) const {
    auto it = ipDeviceMap.find(ip);
    if (it != ipDeviceMap.end()) {
        return it->second;
    }
    return ""; // 찾지 못하면 빈 문자열 반환
}

std::string AssetManager::getDescription(const std::string& translatedAddress) const {
    auto it = tagDescriptionMap.find(translatedAddress);
    if (it != tagDescriptionMap.end()) {
        return it->second;
    }
    return ""; // 찾지 못하면 빈 문자열 반환
}

std::string AssetManager::translateXgtAddress(const std::string& pduVarNm) const {
    // 규칙: %DB001000 -> D500
    if (pduVarNm.empty() || pduVarNm[0] != '%') {
        return "";
    }

    try {
        std::regex re("%([A-Z]{2})([0-9]+)");
        std::smatch match;

        if (std::regex_match(pduVarNm, match, re) && match.size() == 3) {
            std::string type = match[1].str();
            std::string numberStr = match[2].str();
            
            std::string prefix;
            if (type == "DB") prefix = "D";
            else if (type == "MB") prefix = "M";
            else if (type == "PB") prefix = "P";
            else return ""; // 알 수 없는 타입

            int number = std::stoi(numberStr);
            int wordAddress = number / 2; // 바이트 주소 -> 워드 주소

            return prefix + std::to_string(wordAddress);
        }
    } catch (const std::exception& e) {
        // stoi 오류 등
        return "";
    }
    return "";
}

