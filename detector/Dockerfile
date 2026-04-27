FROM python:3.11-slim

# Install iptables for IP blocking and procps for system metrics
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables procps && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/log/detector

CMD ["python", "-u", "main.py"]
