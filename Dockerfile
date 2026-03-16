# Use a base image that has Python
FROM python:3.12-slim

# 1. Install Java, wget, curl, git, AND chromium (Fixed Syntax)
RUN apt-get update && \
    apt-get install -y default-jre wget curl git chromium chromium-driver && \
    rm -rf /var/lib/apt/lists/*

# 2. Install Python Requests for the helper script
RUN pip install requests

# 3. Copy the helper script
COPY get_zap_url.py /tmp/get_zap_url.py

# 4. Dynamically Download & Install ZAP
WORKDIR /opt
RUN URL=$(python3 /tmp/get_zap_url.py) && \
    echo "Downloading ZAP from: $URL" && \
    wget -O zap.tar.gz "$URL" && \
    tar -xvf zap.tar.gz && \
    mv ZAP_* zap && \
    rm zap.tar.gz
    

# CRITICAL: Fix permissions so any user can run ZAP
RUN chmod +x /opt/zap/zap.sh

# 5. Set up the App
WORKDIR /app
COPY . .

# 6. Install Python Dependencies
# We use --no-cache-dir to keep the image small
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# 7. Expose the port (Hugging Face requires 7860)
ENV PORT=7860
EXPOSE 7860

# 8. Start Command: Run ZAP in background, then start Flask via Gunicorn
CMD ["/bin/sh", "-c", "/opt/zap/zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true & sleep 20 && gunicorn -b 0.0.0.0:7860 --workers 1 --threads 8 --timeout 1200 app:app"]