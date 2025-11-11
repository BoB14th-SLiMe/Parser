#include "TimeBasedCsvWriter.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

TimeBasedCsvWriter::TimeBasedCsvWriter(const std::string& output_dir, int interval_minutes)
    : m_output_dir(output_dir), m_interval_minutes(interval_minutes) {
    #ifdef _WIN32
        _mkdir(m_output_dir.c_str());
    #else
        mkdir(m_output_dir.c_str(), 0755);
    #endif
    std::cout << "[INFO] TimeBasedCsvWriter initialized with " << interval_minutes << " minute intervals" << std::endl;
}

TimeBasedCsvWriter::~TimeBasedCsvWriter() {
    // flush는 이미 명시적으로 호출되었으므로 소멸자에서는 하지 않음
    if (!m_time_slots.empty()) {
        std::cout << "[WARN] TimeBasedCsvWriter destroyed with unflushed data!" << std::endl;
        flush();
    }
}

std::string TimeBasedCsvWriter::getTimeSlot(const std::string& timestamp) {
    // timestamp 형식: 2023-05-10T02:24:15.123456Z
    if (timestamp.length() < 19) {
        std::cout << "[WARN] Invalid timestamp format: " << timestamp << std::endl;
        return "";
    }
    
    struct tm tm_time = {};
    std::string ts = timestamp.substr(0, 19);
    
    // 파싱
    sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%d",
           &tm_time.tm_year, &tm_time.tm_mon, &tm_time.tm_mday,
           &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
    
    tm_time.tm_year -= 1900;
    tm_time.tm_mon -= 1;
    
    // 분을 interval 단위로 내림
    int slot_minute = (tm_time.tm_min / m_interval_minutes) * m_interval_minutes;
    tm_time.tm_min = slot_minute;
    tm_time.tm_sec = 0;
    
    // 출력 형식: output_20230510_0224.csv
    std::stringstream ss;
    ss << "output_"
       << std::setfill('0') << std::setw(4) << (tm_time.tm_year + 1900)
       << std::setfill('0') << std::setw(2) << (tm_time.tm_mon + 1)
       << std::setfill('0') << std::setw(2) << tm_time.tm_mday
       << "_"
       << std::setfill('0') << std::setw(2) << tm_time.tm_hour
       << std::setfill('0') << std::setw(2) << slot_minute
       << ".csv";
    
    return ss.str();
}

std::string TimeBasedCsvWriter::escapeCSV(const std::string& s) {
    if (s.empty()) return "";
    if (s.find_first_of(",\"\n") == std::string::npos) {
        return s;
    }
    std::string result = "\"";
    for (char c : s) {
        if (c == '"') {
            result += "\"\"";
        } else {
            result += c;
        }
    }
    result += "\"";
    return result;
}

UnifiedRecord TimeBasedCsvWriter::parseRecord(const std::string& protocol, const std::string& csv_line) {
    UnifiedRecord record;
    record.protocol = protocol;
    
    std::vector<std::string> fields;
    std::stringstream ss(csv_line);
    std::string field;
    bool in_quotes = false;
    std::string current_field;
    
    // CSV 파싱 (따옴표 처리 포함)
    for (char c : csv_line) {
        if (c == '"') {
            in_quotes = !in_quotes;
        } else if (c == ',' && !in_quotes) {
            fields.push_back(current_field);
            current_field.clear();
        } else {
            current_field += c;
        }
    }
    fields.push_back(current_field);
    
    // 공통 필드 (모든 프로토콜)
    if (fields.size() > 0) record.timestamp = fields[0];
    
    if (protocol == "arp") {
        // @timestamp,dir,op,smac,sip,tmac,tip
        if (fields.size() > 1) record.dir = fields[1];
        if (fields.size() > 2) record.arp_op = fields[2];
        if (fields.size() > 3) record.smac = fields[3];
        if (fields.size() > 4) record.sip = fields[4];
        if (fields.size() > 5) record.arp_tmac = fields[5];
        if (fields.size() > 6) record.arp_tip = fields[6];
    }
    else if (protocol == "dns") {
        // @timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,tid,fl.dns,qc,ac
        if (fields.size() > 1) record.smac = fields[1];
        if (fields.size() > 2) record.dmac = fields[2];
        if (fields.size() > 3) record.sip = fields[3];
        if (fields.size() > 4) record.sp = fields[4];
        if (fields.size() > 5) record.dip = fields[5];
        if (fields.size() > 6) record.dp = fields[6];
        if (fields.size() > 7) record.sq = fields[7];      // 추가!
        if (fields.size() > 8) record.ak = fields[8];      // 추가!
        if (fields.size() > 9) record.fl = fields[9];      // 추가!
        if (fields.size() > 10) record.dir = fields[10];
        if (fields.size() > 11) record.dns_tid = fields[11];
        if (fields.size() > 12) record.dns_fl = fields[12];
        if (fields.size() > 13) record.dns_qc = fields[13];
        if (fields.size() > 14) record.dns_ac = fields[14];
    }
    else if (protocol == "dnp3") {
        // @timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,len,ctrl,dest,src
        if (fields.size() > 1) record.smac = fields[1];
        if (fields.size() > 2) record.dmac = fields[2];
        if (fields.size() > 3) record.sip = fields[3];
        if (fields.size() > 4) record.sp = fields[4];
        if (fields.size() > 5) record.dip = fields[5];
        if (fields.size() > 6) record.dp = fields[6];
        if (fields.size() > 7) record.sq = fields[7];      // 추가!
        if (fields.size() > 8) record.ak = fields[8];      // 추가!
        if (fields.size() > 9) record.fl = fields[9];      // 추가!
        if (fields.size() > 10) record.dir = fields[10];
        if (fields.size() > 11) record.dnp3_len = fields[11];
        if (fields.size() > 12) record.dnp3_ctrl = fields[12];
        if (fields.size() > 13) record.dnp3_dest = fields[13];
        if (fields.size() > 14) record.dnp3_src = fields[14];
    }
    else if (protocol == "modbus_tcp") {
        // @timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,tid,pdu.fc,pdu.err,pdu.bc,pdu.addr,pdu.qty,pdu.val,pdu.regs.addr,pdu.regs.val,translated_addr,description
        if (fields.size() > 1) record.smac = fields[1];
        if (fields.size() > 2) record.dmac = fields[2];
        if (fields.size() > 3) record.sip = fields[3];
        if (fields.size() > 4) record.sp = fields[4];
        if (fields.size() > 5) record.dip = fields[5];
        if (fields.size() > 6) record.dp = fields[6];
        if (fields.size() > 7) record.sq = fields[7];      // 추가!
        if (fields.size() > 8) record.ak = fields[8];      // 추가!
        if (fields.size() > 9) record.fl = fields[9];      // 추가!
        if (fields.size() > 10) record.dir = fields[10];
        if (fields.size() > 11) record.modbus_tid = fields[11];
        if (fields.size() > 12) record.modbus_fc = fields[12];
        if (fields.size() > 13) record.modbus_err = fields[13];
        if (fields.size() > 14) record.modbus_bc = fields[14];
        if (fields.size() > 15) record.modbus_addr = fields[15];
        if (fields.size() > 16) record.modbus_qty = fields[16];
        if (fields.size() > 17) record.modbus_val = fields[17];
        if (fields.size() > 18) record.modbus_regs_addr = fields[18];
        if (fields.size() > 19) record.modbus_regs_val = fields[19];
        if (fields.size() > 20) record.modbus_translated_addr = fields[20];
        if (fields.size() > 21) record.modbus_description = fields[21];
    }
    else if (protocol == "s7comm") {
        // @timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,prid,pdu.ros,pdu.prm.fn,pdu.prm.ic,pdu.prm.itms.syn,pdu.prm.itms.tsz,pdu.prm.itms.amt,pdu.prm.itms.db,pdu.prm.itms.ar,pdu.prm.itms.addr,pdu.dat.itms.rc,pdu.dat.itms.len,description
        if (fields.size() > 1) record.smac = fields[1];
        if (fields.size() > 2) record.dmac = fields[2];
        if (fields.size() > 3) record.sip = fields[3];
        if (fields.size() > 4) record.sp = fields[4];
        if (fields.size() > 5) record.dip = fields[5];
        if (fields.size() > 6) record.dp = fields[6];
        if (fields.size() > 7) record.sq = fields[7];      // 추가!
        if (fields.size() > 8) record.ak = fields[8];      // 추가!
        if (fields.size() > 9) record.fl = fields[9];      // 추가!
        if (fields.size() > 10) record.dir = fields[10];
        if (fields.size() > 11) record.s7_prid = fields[11];
        if (fields.size() > 12) record.s7_ros = fields[12];
        if (fields.size() > 13) record.s7_fn = fields[13];
        if (fields.size() > 14) record.s7_ic = fields[14];
        if (fields.size() > 15) record.s7_syn = fields[15];
        if (fields.size() > 16) record.s7_tsz = fields[16];
        if (fields.size() > 17) record.s7_amt = fields[17];
        if (fields.size() > 18) record.s7_db = fields[18];
        if (fields.size() > 19) record.s7_ar = fields[19];
        if (fields.size() > 20) record.s7_addr = fields[20];
        if (fields.size() > 21) record.s7_rc = fields[21];
        if (fields.size() > 22) record.s7_len = fields[22];
        if (fields.size() > 23) record.s7_description = fields[23];
    }
    else if (protocol == "xgt-fen") {
        // @timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,prid,hdr.companyId,hdr.plcinfo,hdr.cpuinfo,hdr.source,hdr.len,hdr.fenetpos,inst.cmd,inst.dtype,inst.blkcnt,inst.errstat,inst.errinfo,inst.vars,inst.datasize,inst.data,translated_addr,description
        if (fields.size() > 1) record.smac = fields[1];
        if (fields.size() > 2) record.dmac = fields[2];
        if (fields.size() > 3) record.sip = fields[3];
        if (fields.size() > 4) record.sp = fields[4];
        if (fields.size() > 5) record.dip = fields[5];
        if (fields.size() > 6) record.dp = fields[6];
        if (fields.size() > 7) record.sq = fields[7];      // 추가!
        if (fields.size() > 8) record.ak = fields[8];      // 추가!
        if (fields.size() > 9) record.fl = fields[9];      // 추가!
        if (fields.size() > 10) record.dir = fields[10];
        if (fields.size() > 11) record.xgt_prid = fields[11];
        if (fields.size() > 12) record.xgt_companyId = fields[12];
        if (fields.size() > 13) record.xgt_plcinfo = fields[13];
        if (fields.size() > 14) record.xgt_cpuinfo = fields[14];
        if (fields.size() > 15) record.xgt_source = fields[15];
        if (fields.size() > 16) record.xgt_len = fields[16];
        if (fields.size() > 17) record.xgt_fenetpos = fields[17];
        if (fields.size() > 18) record.xgt_cmd = fields[18];
        if (fields.size() > 19) record.xgt_dtype = fields[19];
        if (fields.size() > 20) record.xgt_blkcnt = fields[20];
        if (fields.size() > 21) record.xgt_errstat = fields[21];
        if (fields.size() > 22) record.xgt_errinfo = fields[22];
        if (fields.size() > 23) record.xgt_vars = fields[23];
        if (fields.size() > 24) record.xgt_datasize = fields[24];
        if (fields.size() > 25) record.xgt_data = fields[25];
        if (fields.size() > 26) record.xgt_translated_addr = fields[26];
        if (fields.size() > 27) record.xgt_description = fields[27];
    }
    else if (protocol == "tcp_session") {
        // @timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir
        if (fields.size() > 1) record.smac = fields[1];
        if (fields.size() > 2) record.dmac = fields[2];
        if (fields.size() > 3) record.sip = fields[3];
        if (fields.size() > 4) record.sp = fields[4];
        if (fields.size() > 5) record.dip = fields[5];
        if (fields.size() > 6) record.dp = fields[6];
        if (fields.size() > 7) record.sq = fields[7];      // 추가!
        if (fields.size() > 8) record.ak = fields[8];      // 추가!
        if (fields.size() > 9) record.fl = fields[9];      // 추가!
        if (fields.size() > 10) record.dir = fields[10];
    }
    else { // dhcp, ethernet_ip, iec104, mms, opc_ua, bacnet, unknown
        // @timestamp,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,len
        if (fields.size() > 1) record.smac = fields[1];
        if (fields.size() > 2) record.dmac = fields[2];
        if (fields.size() > 3) record.sip = fields[3];
        if (fields.size() > 4) record.sp = fields[4];
        if (fields.size() > 5) record.dip = fields[5];
        if (fields.size() > 6) record.dp = fields[6];
        if (fields.size() > 7) record.sq = fields[7];      // 추가!
        if (fields.size() > 8) record.ak = fields[8];      // 추가!
        if (fields.size() > 9) record.fl = fields[9];      // 추가!
        if (fields.size() > 10) record.dir = fields[10];
        if (fields.size() > 11) record.len = fields[11];
    }
    
    return record;
}

void TimeBasedCsvWriter::addRecord(const std::string& protocol, const std::string& csv_line) {
    UnifiedRecord record = parseRecord(protocol, csv_line);
    std::string time_slot = getTimeSlot(record.timestamp);
    
    if (!time_slot.empty()) {
        m_time_slots[time_slot].push_back(record);
        
        // 주기적으로 로그 출력 (너무 많은 로그를 방지)
        static int log_counter = 0;
        if (++log_counter % 100 == 0) {
            // std::cout << "[INFO] Added record #" << log_counter << " - Protocol: " << protocol 
            //           << ", TimeSlot: " << time_slot 
            //           << ", Total slots: " << m_time_slots.size() << std::endl;
        }
    } else {
        std::cerr << "[ERROR] Empty time slot for timestamp: " << record.timestamp << std::endl;
    }
}

void TimeBasedCsvWriter::writeUnifiedHeader(std::ofstream& out) {
    out << "@timestamp,protocol,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,"
        << "arp.op,arp.tmac,arp.tip,"
        << "dns.tid,dns.fl,dns.qc,dns.ac,"
        << "dnp3.len,dnp3.ctrl,dnp3.dest,dnp3.src,"
        << "len,"
        << "modbus.tid,modbus.fc,modbus.err,modbus.bc,modbus.addr,modbus.qty,modbus.val,modbus.regs.addr,modbus.regs.val,modbus.translated_addr,modbus.description,"
        << "s7.prid,s7.ros,s7.fn,s7.ic,s7.syn,s7.tsz,s7.amt,s7.db,s7.ar,s7.addr,s7.rc,s7.len,s7.description,"
        << "xgt.prid,xgt.companyId,xgt.plcinfo,xgt.cpuinfo,xgt.source,xgt.len,xgt.fenetpos,xgt.cmd,xgt.dtype,xgt.blkcnt,xgt.errstat,xgt.errinfo,xgt.vars,xgt.datasize,xgt.data,xgt.translated_addr,xgt.description\n";
}

void TimeBasedCsvWriter::writeTimeSlot(const std::string& time_slot) {
    if (m_time_slots[time_slot].empty()) {
        std::cout << "[WARN] Time slot " << time_slot << " is empty, skipping" << std::endl;
        return;
    }
    
    std::vector<UnifiedRecord>& records = m_time_slots[time_slot];
    std::sort(records.begin(), records.end(), 
        [](const UnifiedRecord& a, const UnifiedRecord& b) {
            return a.timestamp < b.timestamp;
        });
    
    std::string filepath = m_output_dir + "/" + time_slot;
    std::ofstream out(filepath);
    
    if (!out.is_open()) {
        std::cerr << "[ERROR] Could not open output file " << filepath << std::endl;
        return;
    }
    
    // std::cout << "[INFO] Writing time slot: " << time_slot << " with " << records.size() << " records" << std::endl;
    
    writeUnifiedHeader(out);
    
    for (const auto& record : records) {
        out << escapeCSV(record.timestamp) << ","
            << escapeCSV(record.protocol) << ","
            << escapeCSV(record.smac) << ","
            << escapeCSV(record.dmac) << ","
            << escapeCSV(record.sip) << ","
            << escapeCSV(record.sp) << ","
            << escapeCSV(record.dip) << ","
            << escapeCSV(record.dp) << ","
            << escapeCSV(record.sq) << ","
            << escapeCSV(record.ak) << ","
            << escapeCSV(record.fl) << ","
            << escapeCSV(record.dir) << ","
            << escapeCSV(record.arp_op) << ","
            << escapeCSV(record.arp_tmac) << ","
            << escapeCSV(record.arp_tip) << ","
            << escapeCSV(record.dns_tid) << ","
            << escapeCSV(record.dns_fl) << ","
            << escapeCSV(record.dns_qc) << ","
            << escapeCSV(record.dns_ac) << ","
            << escapeCSV(record.dnp3_len) << ","
            << escapeCSV(record.dnp3_ctrl) << ","
            << escapeCSV(record.dnp3_dest) << ","
            << escapeCSV(record.dnp3_src) << ","
            << escapeCSV(record.len) << ","
            << escapeCSV(record.modbus_tid) << ","
            << escapeCSV(record.modbus_fc) << ","
            << escapeCSV(record.modbus_err) << ","
            << escapeCSV(record.modbus_bc) << ","
            << escapeCSV(record.modbus_addr) << ","
            << escapeCSV(record.modbus_qty) << ","
            << escapeCSV(record.modbus_val) << ","
            << escapeCSV(record.modbus_regs_addr) << ","
            << escapeCSV(record.modbus_regs_val) << ","
            << escapeCSV(record.modbus_translated_addr) << ","
            << escapeCSV(record.modbus_description) << ","
            << escapeCSV(record.s7_prid) << ","
            << escapeCSV(record.s7_ros) << ","
            << escapeCSV(record.s7_fn) << ","
            << escapeCSV(record.s7_ic) << ","
            << escapeCSV(record.s7_syn) << ","
            << escapeCSV(record.s7_tsz) << ","
            << escapeCSV(record.s7_amt) << ","
            << escapeCSV(record.s7_db) << ","
            << escapeCSV(record.s7_ar) << ","
            << escapeCSV(record.s7_addr) << ","
            << escapeCSV(record.s7_rc) << ","
            << escapeCSV(record.s7_len) << ","
            << escapeCSV(record.s7_description) << ","
            << escapeCSV(record.xgt_prid) << ","
            << escapeCSV(record.xgt_companyId) << ","
            << escapeCSV(record.xgt_plcinfo) << ","
            << escapeCSV(record.xgt_cpuinfo) << ","
            << escapeCSV(record.xgt_source) << ","
            << escapeCSV(record.xgt_len) << ","
            << escapeCSV(record.xgt_fenetpos) << ","
            << escapeCSV(record.xgt_cmd) << ","
            << escapeCSV(record.xgt_dtype) << ","
            << escapeCSV(record.xgt_blkcnt) << ","
            << escapeCSV(record.xgt_errstat) << ","
            << escapeCSV(record.xgt_errinfo) << ","
            << escapeCSV(record.xgt_vars) << ","
            << escapeCSV(record.xgt_datasize) << ","
            << escapeCSV(record.xgt_data) << ","
            << escapeCSV(record.xgt_translated_addr) << ","
            << escapeCSV(record.xgt_description) << "\n";
    }
    
    out.close();
    // std::cout << "[SUCCESS] Written " << records.size() << " records to " << filepath << std::endl;
}

void TimeBasedCsvWriter::flush() {
    if (m_time_slots.empty()) {
        // std::cout << "[INFO] No time slots to flush (already flushed or no data)" << std::endl;
        return;
    }
    
    // std::cout << "[INFO] Flushing TimeBasedCsvWriter - " << m_time_slots.size() << " time slots to write" << std::endl;
    
    for (const auto& slot : m_time_slots) {
        // std::cout << "[INFO] Processing time slot: " << slot.first 
        //           << " with " << slot.second.size() << " records" << std::endl;
        writeTimeSlot(slot.first);
    }
    
    m_time_slots.clear();
    std::cout << "[INFO] Flush complete" << std::endl;
}