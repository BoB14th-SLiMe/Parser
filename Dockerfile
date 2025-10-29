# ============================================
# C++ Parser - Dockerfile
# ============================================
# RealtimeParser/build/parser 바이너리를 실행하는 경량 이미지

FROM ubuntu:22.04

# 필수 런타임 라이브러리 설치
RUN apt-get update && apt-get install -y \
    libstdc++6 \
    libgcc-s1 \
    libc6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 생성
WORKDIR /app

# 빌드된 parser 바이너리 복사
COPY build/parser /app/parser

# 설정 파일 복사
COPY config.json /app/config.json

# 실행 권한 부여
RUN chmod +x /app/parser

# 로그 디렉토리 생성
RUN mkdir -p /app/logs

# 출력 디렉토리 생성
RUN mkdir -p /data/parser-output

# 환경 변수 설정
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379
ENV KAFKA_BOOTSTRAP_SERVERS=kafka:29092
ENV OUTPUT_DIR=/data/parser-output

# 실행
CMD ["/app/parser"]
