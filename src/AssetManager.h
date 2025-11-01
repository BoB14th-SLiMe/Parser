#ifndef ASSET_MANAGER_H
#define ASSET_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <set>

// 디바이스별 Modbus 설정 정보
struct ModbusDeviceConfig {
    std::string ip;
    int port;
    int unit_id;
    std::string description;
    std::string communication_note;
    std::string remark;
    
    // 어드레스 계산 방식 (예: "Page# * 256 + offset", "standard" 등)
    std::string address_calculation_method;
};

// 레지스터 매핑 정보
struct RegisterMapping {
    std::string device_ip;
    int device_port;
    int function_code;
    unsigned long register_address;
    std::string translated_address;
    std::string description;
};

class AssetManager {
public:
    // CSV 파일들을 로드합니다.
    AssetManager(const std::string& ipCsvPath, 
                 const std::string& inputCsvPath, 
                 const std::string& outputCsvPath);

    // IP 주소로 장치 이름을 찾습니다.
    std::string getDeviceName(const std::string& ip) const;

    // 변환된 주소(태그)로 'description' (내용)을 찾습니다.
    std::string getDescription(const std::string& translatedAddress) const;

    // XGT 주소 변환 규칙을 적용합니다.
    std::string translateXgtAddress(const std::string& pduVarNm) const;

    // Modbus 주소 변환 규칙을 적용합니다.
    std::string translateModbusAddress(const std::string& fc, unsigned long addr) const;

    // S7Comm 주소 변환 규칙을 적용합니다.
    std::string translateS7Address(const std::string& area, const std::string& db, const std::string& addr) const;
    
    // === 새로운 메서드: 디바이스별 Modbus 레지스터 매핑 ===
    
    // IP, Port, Function Code, Register Address로 레지스터 정보 조회
    bool getRegisterInfo(const std::string& ip, int port, int fc, unsigned long addr,
                         std::string& translated_addr, std::string& description) const;
    
    // 디바이스 설정 정보 조회
    const ModbusDeviceConfig* getDeviceConfig(const std::string& ip, int port) const;
    
    // asset_참조.csv 로드
    void loadAssetReferenceCsv(const std::string& filepath);
    
    // 개별 asset CSV 파일들 로드 (PCS, Generator 등)
    void loadAssetDeviceCsvs(const std::vector<std::string>& filepaths);

private:
    // CSV 파일을 읽어 맵에 저장하는 헬퍼 함수
    void loadIpCsv(const std::string& filepath);
    void loadTagCsv(const std::string& filepath);
    
    // 어드레스 계산 헬퍼
    unsigned long calculateActualAddress(const ModbusDeviceConfig& config, 
                                        int fc, unsigned long raw_addr) const;

    // 맵: IP -> 장치 이름
    std::map<std::string, std::string> ipDeviceMap;
    
    // 맵: 태그 주소 -> 설명 (description)
    std::map<std::string, std::string> tagDescriptionMap;
    
    // 맵: IP+Port -> 디바이스 설정
    std::map<std::string, ModbusDeviceConfig> deviceConfigMap;
    
    // 맵: "IP:Port:FC:Addr" -> RegisterMapping
    std::map<std::string, RegisterMapping> registerMappingMap;
};

#endif // ASSET_MANAGER_H