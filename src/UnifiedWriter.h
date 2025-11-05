#ifndef UNIFIED_WRITER_H
#define UNIFIED_WRITER_H

#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <mutex>
#include <ctime>

// 통합 레코드 구조체
struct UnifiedRecord {
    std::string timestamp;
    std::string protocol;
    std::string smac;
    std::string dmac;
    std::string sip;
    std::string sp;
    std::string dip;
    std::string dp;
    std::string sq;
    std::string ak;
    std::string fl;
    std::string dir;
    
    // 프로토콜별 상세 정보 (JSON 형태)
    std::string details_json;
    
    // 프로토콜별 CSV 필드
    std::string arp_op;
    std::string arp_tmac;
    std::string arp_tip;
    
    std::string dns_tid;
    std::string dns_fl;
    std::string dns_qc;
    std::string dns_ac;
    
    std::string dnp3_len;
    std::string dnp3_ctrl;
    std::string dnp3_dest;
    std::string dnp3_src;
    
    std::string len;
    
    std::string modbus_tid;
    std::string modbus_fc;
    std::string modbus_err;
    std::string modbus_bc;
    std::string modbus_addr;
    std::string modbus_qty;
    std::string modbus_val;
    std::string modbus_regs_addr;
    std::string modbus_regs_val;
    std::string modbus_translated_addr;
    std::string modbus_description;
    
    std::string s7_prid;
    std::string s7_ros;
    std::string s7_fn;
    std::string s7_ic;
    std::string s7_syn;
    std::string s7_tsz;
    std::string s7_amt;
    std::string s7_db;
    std::string s7_ar;
    std::string s7_addr;
    std::string s7_rc;
    std::string s7_len;
    std::string s7_description;
    
    std::string xgt_prid;
    std::string xgt_companyId;
    std::string xgt_plcinfo;
    std::string xgt_cpuinfo;
    std::string xgt_source;
    std::string xgt_len;
    std::string xgt_fenetpos;
    std::string xgt_cmd;
    std::string xgt_dtype;
    std::string xgt_blkcnt;
    std::string xgt_errstat;
    std::string xgt_errinfo;
    std::string xgt_vars;
    std::string xgt_datasize;
    std::string xgt_data;
    std::string xgt_translated_addr;
    std::string xgt_description;
};

class UnifiedWriter {
public:
    UnifiedWriter(const std::string& output_dir, int interval_minutes);
    ~UnifiedWriter();
    
    // 레코드 추가 (스레드 안전)
    void addRecord(const UnifiedRecord& record);
    
    // 파일 플러시 및 로테이션
    void flush();
    
private:
    std::string m_output_dir;
    int m_interval_minutes;
    
    // 시간 슬롯별로 레코드 저장
    std::map<std::string, std::vector<UnifiedRecord>> m_time_slots;
    std::mutex m_mutex;
    
    // 타임스탬프로부터 시간 슬롯 계산
    std::string getTimeSlot(const std::string& timestamp);
    
    // 시간 슬롯별 파일 작성
    void writeTimeSlot(const std::string& time_slot);
    
    // CSV/JSONL 헤더 작성
    void writeCsvHeader(std::ofstream& out);
    
    // CSV 이스케이프
    std::string escapeCSV(const std::string& s);
};

#endif // UNIFIED_WRITER_H