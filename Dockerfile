FROM python:3.9-slim

WORKDIR /app

# Install system dependencies required for scapy
RUN apt-get update && apt-get install -y \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose API port
EXPOSE 8000

# Run the application
CMD ["python", "main.py", "api", "--host", "0.0.0.0"]
