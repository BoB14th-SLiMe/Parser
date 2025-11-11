#ifndef ASSET_MANAGER_H
#define ASSET_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <set>

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

private:
    // CSV 파일을 읽어 맵에 저장하는 헬퍼 함수
    void loadIpCsv(const std::string& filepath);
    void loadTagCsv(const std::string& filepath);

    // 맵: IP -> 장치 이름
    std::map<std::string, std::string> ipDeviceMap;
    
    // 맵: 태그 주소 -> 설명 (description)
    std::map<std::string, std::string> tagDescriptionMap;
};

#endif // ASSET_MANAGER_H