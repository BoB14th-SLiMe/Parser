# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04 AS builder

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the parser source code (Corrected paths relative to build context)
COPY ./src ./src
COPY ./CMakeLists.txt ./
COPY ./assets ./assets

# Build the parser
RUN cmake -B build && \
    cmake --build build

# --- Final Stage ---
# Use a smaller base image for the final image
FROM ubuntu:22.04

# Install runtime dependencies (libpcap0.8)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the built parser executable and assets from the builder stage
COPY --from=builder /app/build/parser .
COPY --from=builder /app/assets ./assets

# Copy the entrypoint script (Corrected path relative to build context)
COPY ./entrypoint.sh .
RUN chmod +x ./entrypoint.sh

# Create output directory
RUN mkdir -p /app/output

# Run the entrypoint script when the container starts
ENTRYPOINT ["./entrypoint.sh"]

