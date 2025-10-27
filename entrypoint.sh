#!/bin/bash

echo "파서 서비스 시작됨. pcap 파일을 기다리는 중..."

# pcap 파일 경로 정의
PCAP_FILE="/pcap/output.pcap"
OUTPUT_DIR="/app/output"

# 대기 루프: pcap 파일 존재 여부 확인 및 파일 쓰기 완료 대기
# 간단한 초기 sleep 후 파일 안정성 확인.
# tshark가 지원한다면 시그널이나 파일 잠금을 사용하는 것이 더 견고할 수 있음.
sleep 70 # tshark가 60초 캡처를 완료하고 파일을 쓸 충분한 시간 제공.

# pcap 파일 존재 여부 확인
if [ ! -f "$PCAP_FILE" ]; then
  echo "오류: 대기 후 $PCAP_FILE 파일을 찾을 수 없습니다."
  exit 1
fi

echo "Pcap 파일 발견됨. 파서 실행 중..."

# 컨테이너 내 output 디렉토리 존재 확인 및 생성
mkdir -p "$OUTPUT_DIR"

# 캡처된 파일에 대해 파서 실행
./parser "$PCAP_FILE"

# 파서 종료 코드 확인
if [ $? -eq 0 ]; then
  echo "파서가 성공적으로 완료되었습니다."
  echo "출력 파일은 마운트된 'output' 디렉토리에 있습니다."
else
  echo "오류: 파서 실행 실패."
  exit 1
fi

# 필요시 검사를 위해 컨테이너를 계속 실행 상태로 유지. 그렇지 않으면 여기서 종료됨.
# tail -f /dev/null

