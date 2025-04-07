FROM ubuntu:20.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y isc-dhcp-server net-tools iputils-ping

COPY dhcpd.conf /etc/dhcp/dhcpd.conf

RUN mkdir -p /var/lib/dhcp && touch /var/lib/dhcp/dhcpd.leases

# Create entrypoint script
RUN echo '#!/bin/bash\n\
# Get the interface name\n\
IFACE=$(ip -o -4 route show to default | awk "{print \$5}")\n\
echo "Starting DHCP server on interface: $IFACE"\n\
\n\
# Run dhcpd in foreground mode\n\
exec dhcpd -f -d -4 --no-pid $IFACE\n\
' > /entrypoint.sh

RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
