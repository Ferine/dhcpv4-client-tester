FROM python:3.10-slim

RUN apt-get update && apt-get install -y net-tools iputils-ping iproute2

COPY dhcp_simulator.py /app/dhcp_simulator.py

WORKDIR /app

# Wait for interface to be fully up with proper routing
CMD ["bash", "-c", "sleep 5 && python3 dhcp_simulator.py"]
