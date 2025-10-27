#include "AssetManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>

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
    fields.push_back(field);
    return fields;
}

// 문자열 trim 헬퍼 함수
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, last - first + 1);
}

// IP 주소 정규화 함수 (192,168.10.25 -> 192.168.10.25)
std::string normalizeIp(const std::string& ip) {
    std::string normalized = ip;
    
    // 쉼표를 점으로 변경
    std::replace(normalized.begin(), normalized.end(), ',', '.');
    
    // modbus 포트 제거 (192.168.1.22/502 -> 192.168.1.22)
    size_t slash_pos = normalized.find('/');
    if (slash_pos != std::string::npos) {
        normalized = normalized.substr(0, slash_pos);
    }
    
    // "modbus: " 접두사 제거
    if (normalized.find("modbus:") != std::string::npos) {
        size_t colon_pos = normalized.find(':');
        if (colon_pos != std::string::npos) {
            normalized = normalized.substr(colon_pos + 1);
            normalized = trim(normalized);
            // 다시 포트 제거
            slash_pos = normalized.find('/');
            if (slash_pos != std::string::npos) {
                normalized = normalized.substr(0, slash_pos);
            }
        }
    }
    
    return trim(normalized);
}

// IP 주소 유효성 검사
bool isValidIp(const std::string& ip) {
    if (ip.empty()) return false;
    
    // 점이 정확히 3개 있어야 함
    int dot_count = std::count(ip.begin(), ip.end(), '.');
    if (dot_count != 3) return false;
    
    // 각 옥텟이 0-255 범위인지 확인
    std::regex ip_regex(
        R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );
    return std::regex_match(ip, ip_regex);
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

// 자산IP CSV 로드 (신규 형식 대응)
void AssetManager::loadIpCsv(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file.");
    }

    std::string line;
    int line_number = 0;
    bool header_skipped = false;
    
    // 이전 Device Name을 기억 (빈 줄 처리용)
    std::string last_device_name;
    
    while (std::getline(file, line)) {
        line_number++;
        
        // 빈 줄 스킵
        if (trim(line).empty()) {
            continue;
        }
        
        // 헤더 행 스킵 (첫 번째 줄)
        if (!header_skipped) {
            if (line.find("Device Name") != std::string::npos || 
                line.find("IP") != std::string::npos) {
                header_skipped = true;
                std::cout << "[INFO] CSV header found and skipped." << std::endl;
                continue;
            }
        }
        
        std::vector<std::string> fields = parseCsvRow(line);
        
        // 최소 2개 필드 필요 (Device Name, IP)
        if (fields.size() < 2) {
            std::cout << "[WARN] Line " << line_number << " has insufficient fields, skipping." << std::endl;
            continue;
        }
        
        std::string device_name = trim(fields[0]);
        std::string ip_raw = trim(fields[1]);
        
        // IP 정규화
        std::string ip = normalizeIp(ip_raw);
        
        // Device Name이 비어있으면 이전 이름 사용
        if (device_name.empty() && !last_device_name.empty()) {
            device_name = last_device_name + " (secondary)";
        }
        
        // IP 유효성 검사
        if (!isValidIp(ip)) {
            if (!ip.empty()) {
                std::cout << "[WARN] Line " << line_number << ": Invalid IP '" 
                         << ip_raw << "' (normalized: '" << ip << "'), skipping." << std::endl;
            }
            continue;
        }
        
        // Device Name이 없고 이전 이름도 없으면 IP만으로 식별
        if (device_name.empty()) {
            device_name = "Unknown Device (" + ip + ")";
        }
        
        // 매핑 추가
        ipDeviceMap[ip] = device_name;
        last_device_name = device_name;
        
        std::cout << "[DEBUG] Mapped: " << ip << " -> " << device_name << std::endl;
    }
    
    std::cout << "[INFO] Loaded " << ipDeviceMap.size() << " IP-to-Device mappings." << std::endl;
}

// 유선_Input / 유선_Output CSV 로드 (기존 유지)
void AssetManager::loadTagCsv(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file.");
    }

    // Check for BOM
    char bom[3];
    file.read(bom, 3);
    if (file.gcount() != 3 || bom[0] != (char)0xEF || bom[1] != (char)0xBB || bom[2] != (char)0xBF) {
        file.seekg(0);
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
                if (static_cast<size_t>(col) < fields.size()) {
                    std::string tag = fields[col];
                    if (!tag.empty()) {
                        tag = trim(tag);
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
    return "";
}

std::string AssetManager::getDescription(const std::string& translatedAddress) const {
    auto it = tagDescriptionMap.find(translatedAddress);
    if (it != tagDescriptionMap.end()) {
        return it->second;
    }
    return "";
}

std::string AssetManager::translateXgtAddress(const std::string& pduVarNm) const {
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
            else return "";

            int number = std::stoi(numberStr);
            int wordAddress = number / 2;

            return prefix + std::to_string(wordAddress);
        }
    } catch (const std::exception& e) {
        return "";
    }
    return "";
}

std::string AssetManager::translateModbusAddress(const std::string& fc_str, unsigned long addr) const {
    if (fc_str.empty()) return "";
    try {
        int fc = std::stoi(fc_str);
        long offset = 0;
        switch (fc) {
            case 0:
                offset = 1;
                break;
            case 1:
            case 2:
                offset = 10001;
                break;
            case 3:
                offset = 300001;
                break;
            case 4:
                offset = 400001;
                break;
            default:
                return std::to_string(addr);
        }
        return std::to_string(offset + addr);
    } catch (const std::exception& e) {
        return "";
    }
}

std::string AssetManager::translateS7Address(const std::string& area_str, const std::string& db_str, const std::string& addr_str) const {
    if (area_str != "132") { // 0x84
        return "";
    }
    return "DB" + db_str + "," + addr_str;
}