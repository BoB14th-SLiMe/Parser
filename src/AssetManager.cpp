#include "AssetManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>

// CSV 파싱 헬퍼 함수들 (동일)
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

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, last - first + 1);
}

std::string normalizeIp(const std::string& ip) {
    std::string normalized = ip;
    std::replace(normalized.begin(), normalized.end(), ',', '.');
    size_t slash_pos = normalized.find('/');
    if (slash_pos != std::string::npos) {
        normalized = normalized.substr(0, slash_pos);
    }
    if (normalized.find("modbus:") != std::string::npos) {
        size_t colon_pos = normalized.find(':');
        if (colon_pos != std::string::npos) {
            normalized = normalized.substr(colon_pos + 1);
            normalized = trim(normalized);
            slash_pos = normalized.find('/');
            if (slash_pos != std::string::npos) {
                normalized = normalized.substr(0, slash_pos);
            }
        }
    }
    return trim(normalized);
}

bool isValidIp(const std::string& ip) {
    if (ip.empty()) return false;
    int dot_count = std::count(ip.begin(), ip.end(), '.');
    if (dot_count != 3) return false;
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
        std::cerr << "Warning: Could not load IP CSV file. " << e.what() << std::endl;
    }
    try {
        loadTagCsv(inputCsvPath);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not load Input Tag CSV file. " << e.what() << std::endl;
    }
    try {
        loadTagCsv(outputCsvPath);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not load Output Tag CSV file. " << e.what() << std::endl;
    }

    try {
        loadAssetReferenceCsv("assets/asset_참조.csv");
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not load asset reference CSV. " << e.what() << std::endl;
    }

    std::vector<std::string> asset_files = {
        "assets/asset_PCS.csv",
        "assets/asset_Power Simulator.csv",
        "assets/asset_Generator 2.csv"
    };
    try {
        loadAssetDeviceCsvs(asset_files);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Could not load asset device CSVs. " << e.what() << std::endl;
    }

    std::cout << "AssetManager initialized." << std::endl;
    std::cout << "  - IP entries: " << ipDeviceMap.size() << std::endl;
    std::cout << "  - Device configs: " << deviceConfigMap.size() << std::endl;
    std::cout << "  - Register mappings: " << registerMappingMap.size() << std::endl;
}

void AssetManager::loadAssetReferenceCsv(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open asset reference file.");
    }

    std::string line;
    bool header_skipped = false;
    
    while (std::getline(file, line)) {
        if (trim(line).empty()) continue;
        
        if (!header_skipped) {
            if (line.find("IP Address") != std::string::npos) {
                header_skipped = true;
                continue;
            }
        }
        
        std::vector<std::string> fields = parseCsvRow(line);
        if (fields.size() < 6) continue;
        
        std::string ip_raw = trim(fields[0]);
        std::string port_str = trim(fields[1]);
        std::string unit_id_str = trim(fields[2]);
        std::string description = trim(fields[3]);
        std::string comm_test = trim(fields[4]);
        std::string remark = trim(fields[5]);
        
        std::string ip = normalizeIp(ip_raw);
        if (!isValidIp(ip)) continue;
        
        int port = 502;
        int unit_id = 0;
        
        try {
            if (!port_str.empty()) port = std::stoi(port_str);
            if (!unit_id_str.empty()) unit_id = std::stoi(unit_id_str);
        } catch (...) {
            continue;
        }
        
        ModbusDeviceConfig config;
        config.ip = ip;
        config.port = port;
        config.unit_id = unit_id;
        config.description = description;
        config.communication_note = comm_test;
        config.remark = remark;
        
        if (comm_test.find("Page# * 256 + offset") != std::string::npos) {
            config.address_calculation_method = "page_offset_256";
        } else if (comm_test.find("RTU 프로토콜") != std::string::npos) {
            config.address_calculation_method = "rtu_in_tcp";
        } else if (comm_test.find("1번 어드레스 시작") != std::string::npos) {
            config.address_calculation_method = "one_based";
        } else {
            config.address_calculation_method = "standard";
        }
        
        std::string key = ip + ":" + std::to_string(port);
        deviceConfigMap[key] = config;
        
        std::cout << "[DEBUG] Device config: " << key << " -> " << description 
                  << " (method: " << config.address_calculation_method << ")" << std::endl;
    }
    
    std::cout << "[INFO] Loaded " << deviceConfigMap.size() << " device configurations" << std::endl;
}

void AssetManager::parseValueMappingCsv(const std::string& filepath, 
                                        const std::string& device_ip, 
                                        int device_port) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[WARN] Could not open value mapping file: " << filepath << std::endl;
        return;
    }

    std::string line;
    bool header_found = false;
    int address_col = -1, min_val_col = -1, max_val_col = -1, name_col = -1, bit_col = -1;
    
    int line_num = 0;
    while (std::getline(file, line)) {
        line_num++;
        if (trim(line).empty()) continue;
        
        std::vector<std::string> fields = parseCsvRow(line);
        
        // 헤더 찾기
        if (!header_found) {
            for (size_t i = 0; i < fields.size(); i++) {
                std::string header = trim(fields[i]);
                if (header == "Address" || header == "address") address_col = i;
                else if (header == "Min" || header == "min") min_val_col = i;
                else if (header == "Max" || header == "max") max_val_col = i;
                else if (header == "Name" || header == "name") name_col = i;
                else if (header == "Bit" || header == "bit") bit_col = i;
            }
            
            if (address_col >= 0 && name_col >= 0) {
                header_found = true;
                std::cout << "[INFO] Value mapping header found at line " << line_num << std::endl;
                continue;
            }
        }
        
        if (!header_found) continue;
        
        // 데이터 파싱
        if (fields.size() <= (size_t)std::max({address_col, min_val_col, max_val_col, name_col})) {
            continue;
        }
        
        try {
            std::string addr_str = trim(fields[address_col]);
            std::string name = trim(fields[name_col]);
            
            if (addr_str.empty() || name.empty()) continue;
            
            unsigned long address = std::stoul(addr_str);
            
            // Min/Max 값 파싱
            unsigned long min_val = 0, max_val = 0;
            bool has_range = false;
            
            if (min_val_col >= 0 && (size_t)min_val_col < fields.size()) {
                std::string min_str = trim(fields[min_val_col]);
                if (!min_str.empty() && std::isdigit(min_str[0])) {
                    min_val = std::stoul(min_str);
                    has_range = true;
                }
            }
            
            if (max_val_col >= 0 && (size_t)max_val_col < fields.size()) {
                std::string max_str = trim(fields[max_val_col]);
                if (!max_str.empty() && std::isdigit(max_str[0])) {
                    max_val = std::stoul(max_str);
                }
            } else if (has_range) {
                max_val = min_val; // Max가 없으면 Min과 동일
            }
            
            // Bit 정보 (선택적)
            std::string bit_info = "";
            if (bit_col >= 0 && (size_t)bit_col < fields.size()) {
                bit_info = trim(fields[bit_col]);
            }
            
            // 레지스터 매핑 키 생성 (FC는 3으로 가정)
            int fc = 3;
            std::string mapping_key = device_ip + ":" + std::to_string(device_port) + 
                                     ":" + std::to_string(fc) + ":" + std::to_string(address);
            
            // 기존 매핑이 없으면 생성
            if (registerMappingMap.find(mapping_key) == registerMappingMap.end()) {
                RegisterMapping mapping;
                mapping.device_ip = device_ip;
                mapping.device_port = device_port;
                mapping.function_code = fc;
                mapping.register_address = address;
                mapping.register_name = "Register " + std::to_string(address);
                mapping.has_value_mapping = true;
                registerMappingMap[mapping_key] = mapping;
            }
            
            // 값-설명 매핑 추가
            auto& mapping = registerMappingMap[mapping_key];
            mapping.has_value_mapping = true;
            
            if (has_range) {
                // Min~Max 범위의 모든 값에 동일한 설명 적용
                for (unsigned long val = min_val; val <= max_val; val++) {
                    mapping.value_description_map[val] = name;
                }
                std::cout << "[DEBUG] Value mapping: " << mapping_key 
                         << " values[" << min_val << "-" << max_val << "] -> \"" << name << "\"" << std::endl;
            } else {
                // Min 값만 단일 매핑
                mapping.value_description_map[min_val] = name;
                std::cout << "[DEBUG] Value mapping: " << mapping_key 
                         << " value[" << min_val << "] -> \"" << name << "\"" << std::endl;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[WARN] Failed to parse value mapping at line " << line_num 
                     << ": " << e.what() << std::endl;
            continue;
        }
    }
}

void AssetManager::loadAssetDeviceCsvs(const std::vector<std::string>& filepaths) {
    for (const auto& filepath : filepaths) {
        std::cout << "[INFO] Loading device CSV: " << filepath << std::endl;
        
        // 파일명에서 디바이스 이름 추출
        std::string device_name = "";
        std::string device_ip = "";
        int device_port = 502;
        
        size_t pos = filepath.find("asset_");
        if (pos != std::string::npos) {
            device_name = filepath.substr(pos + 6);
            size_t dot_pos = device_name.find(".csv");
            if (dot_pos != std::string::npos) {
                device_name = device_name.substr(0, dot_pos);
                
                // deviceConfigMap에서 해당 디바이스 찾기
                for (const auto& pair : deviceConfigMap) {
                    if (pair.second.description.find(device_name) != std::string::npos ||
                        device_name.find(pair.second.description) != std::string::npos) {
                        device_ip = pair.second.ip;
                        device_port = pair.second.port;
                        std::cout << "[INFO] Matched device: " << device_name 
                                 << " -> " << device_ip << ":" << device_port << std::endl;
                        break;
                    }
                }
            }
        }
        
        if (device_ip.empty()) {
            std::cerr << "[WARN] Could not match device for file: " << filepath << std::endl;
            continue;
        }
        
        // 값 기반 매핑 파일 파싱
        parseValueMappingCsv(filepath, device_ip, device_port);
    }
    
    std::cout << "[INFO] Total register mappings: " << registerMappingMap.size() << std::endl;
}

bool AssetManager::getRegisterInfoWithValue(const std::string& ip, int port, int fc, 
                                            unsigned long addr, unsigned long value,
                                            std::string& translated_addr, 
                                            std::string& description,
                                            std::string& register_name) const {
    std::string device_key = ip + ":" + std::to_string(port);
    auto device_it = deviceConfigMap.find(device_key);
    
    if (device_it == deviceConfigMap.end()) {
        translated_addr = translateModbusAddress(std::to_string(fc), addr);
        description = "";
        register_name = "";
        return false;
    }
    
    const ModbusDeviceConfig& config = device_it->second;
    unsigned long actual_addr = calculateActualAddress(config, fc, addr);
    
    std::string mapping_key = ip + ":" + std::to_string(port) + ":" + 
                             std::to_string(fc) + ":" + std::to_string(actual_addr);
    
    auto mapping_it = registerMappingMap.find(mapping_key);
    
    if (mapping_it != registerMappingMap.end()) {
        const RegisterMapping& mapping = mapping_it->second;
        register_name = mapping.register_name;
        translated_addr = translateModbusAddress(std::to_string(fc), actual_addr);
        
        // 값 기반 매핑이 있는 경우
        if (mapping.has_value_mapping) {
            auto value_it = mapping.value_description_map.find(value);
            if (value_it != mapping.value_description_map.end()) {
                description = value_it->second;
                return true;
            } else {
                // 매핑에 없는 값
                description = register_name + " = " + std::to_string(value) + " (Unknown)";
                return true;
            }
        } else {
            // 값 매핑이 없으면 기본 설명
            description = register_name;
            return true;
        }
    }
    
    // 매핑이 없으면 기본 변환
    translated_addr = translateModbusAddress(std::to_string(fc), actual_addr);
    description = config.description + " - Register " + std::to_string(actual_addr);
    register_name = "Register " + std::to_string(actual_addr);
    return false;
}

unsigned long AssetManager::calculateActualAddress(const ModbusDeviceConfig& config, 
                                                   int fc, unsigned long raw_addr) const {
    if (config.address_calculation_method == "page_offset_256") {
        // Page# * 256 + offset 방식
        // 실제 레지스터 매핑을 위해 그대로 사용
        // 예: 2050 = Page 8, Offset 2
        return raw_addr;
    } else if (config.address_calculation_method == "one_based") {
        return raw_addr > 0 ? raw_addr - 1 : 0;
    } else if (config.address_calculation_method == "rtu_in_tcp") {
        return raw_addr;
    }
    return raw_addr;
}

const ModbusDeviceConfig* AssetManager::getDeviceConfig(const std::string& ip, int port) const {
    std::string key = ip + ":" + std::to_string(port);
    auto it = deviceConfigMap.find(key);
    if (it != deviceConfigMap.end()) {
        return &it->second;
    }
    return nullptr;
}

void AssetManager::loadIpCsv(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file.");
    }

    std::string line;
    bool header_skipped = false;
    std::string last_device_name;
    
    while (std::getline(file, line)) {
        if (trim(line).empty()) continue;
        
        if (!header_skipped) {
            if (line.find("Device Name") != std::string::npos) {
                header_skipped = true;
                continue;
            }
        }
        
        std::vector<std::string> fields = parseCsvRow(line);
        if (fields.size() < 2) continue;
        
        std::string device_name = trim(fields[0]);
        std::string ip_raw = trim(fields[1]);
        std::string ip = normalizeIp(ip_raw);
        
        if (device_name.empty() && !last_device_name.empty()) {
            device_name = last_device_name + " (secondary)";
        }
        
        if (!isValidIp(ip)) continue;
        
        if (device_name.empty()) {
            device_name = "Unknown Device (" + ip + ")";
        }
        
        ipDeviceMap[ip] = device_name;
        last_device_name = device_name;
    }
}

void AssetManager::loadTagCsv(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file.");
    }

    char bom[3];
    file.read(bom, 3);
    if (file.gcount() != 3 || bom[0] != (char)0xEF || bom[1] != (char)0xBB || bom[2] != (char)0xBF) {
        file.seekg(0);
    }

    std::string line;
    std::getline(file, line);
    std::set<int> tagColumns = {3, 4, 5, 6, 7};

    while (std::getline(file, line)) {
        std::vector<std::string> fields = parseCsvRow(line);
        if (fields.size() > 1) {
            std::string description = fields[1];
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
    if (pduVarNm.empty() || pduVarNm[0] != '%') return "";
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
            case 0: offset = 1; break;
            case 1:
            case 2: offset = 10001; break;
            case 3: offset = 300001; break;
            case 4: offset = 400001; break;
            default: return std::to_string(addr);
        }
        return std::to_string(offset + addr);
    } catch (const std::exception& e) {
        return "";
    }
}

std::string AssetManager::translateS7Address(const std::string& area_str, const std::string& db_str, const std::string& addr_str) const {
    if (area_str != "132") return "";
    return "DB" + db_str + "," + addr_str;
}