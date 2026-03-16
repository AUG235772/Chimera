FROM python:3.12-slim

# 1. Install System Dependencies (Added 'unzip' for Nuclei)
RUN apt-get update && \
    apt-get install -y default-jre wget curl git chromium chromium-driver unzip && \
    rm -rf /var/lib/apt/lists/*

# 2. ☢️ INSTALL NUCLEI (The Zero-Day / CVE Engine)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip && \
    unzip nuclei_3.3.0_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.3.0_linux_amd64.zip && \
    nuclei -update-templates

# 3. Install Python Requests for the helper script
RUN pip install requests

# 4. Dynamically Download & Install ZAP
COPY get_zap_url.py /tmp/get_zap_url.py
WORKDIR /opt
RUN URL=$(python3 /tmp/get_zap_url.py) && \
    echo "Downloading ZAP from: $URL" && \
    wget -O zap.tar.gz "$URL" && \
    tar -xvf zap.tar.gz && \
    mv ZAP_* zap && \
    rm zap.tar.gz
RUN chmod +x /opt/zap/zap.sh

# 5. Set up the App
WORKDIR /app
COPY . .

# 6. Install Python Dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# 7. Expose the port
ENV PORT=7860
EXPOSE 7860

# 8. Start Command
CMD ["/bin/sh", "-c", "/opt/zap/zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true & sleep 20 && gunicorn -b 0.0.0.0:7860 --workers 1 --threads 8 --timeout 1200 app:app"]