#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#include <unistd.h>

ssize_t create_ip_packet(char * buffer,
        size_t buffer_capacity,
        const char* source_address,
        const char* dest_address,
        const void* payload,
        size_t payload_length,
        uint8_t protocol){
    struct iphdr *iph;
    size_t header_length;
    size_t total_length;

    header_length = sizeof(struct iphdr);
    total_length = header_length + payload_length;

    if (total_length > buffer_capacity) {
        printf("Buffer capacity %zu insufficient for total datagram length %zu\n",
                buffer_capacity, total_length);
        return -1;
    }

    iph = (struct iphdr *) buffer;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_length); // seems to be overwritten by kernel
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = protocol;
    iph->check = 0; // seems to be overwritten by kernel - not with packet sockets. TODO: actually calculate it
    iph->saddr = inet_addr(source_address);
    iph->daddr = inet_addr(dest_address);

    // copy the payload into buffer after header
    memcpy(buffer + header_length, payload, payload_length);

    return total_length;
}

int send_ip_datagram(const const char* source_address,
        const const char* dest_address,
        const const void* payload,
        size_t payload_length,
        uint8_t protocol) {
    int socket_desc = 0;
    char datagram[2048];
    ssize_t ip_datagram_length;
    struct sockaddr_in destination;
    int retv; // scratch for return values

    memset(datagram, 0, sizeof(datagram));

    // set up socket
    socket_desc = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_desc == -1) {
        perror("Could not create socket");
        return -1;
    }
    int enable_headers_included = 1;
    retv = setsockopt(socket_desc, IPPROTO_IP, IP_HDRINCL,
            &enable_headers_included,
            sizeof (enable_headers_included));
    if (retv != 0) {
        perror("Couldn't set headers included option");
        return -1;
    }

    ip_datagram_length = create_ip_packet(datagram, sizeof(datagram),
            source_address, dest_address,
            payload, payload_length, protocol);
    if (ip_datagram_length < 0) {
        printf("Error creating ip packet\n");
        return -1;
    }

    // send the datagram
    destination.sin_family = AF_INET;
    destination.sin_addr.s_addr = inet_addr(dest_address);
    retv = sendto(socket_desc, datagram, ip_datagram_length, 0,
            (struct sockaddr *) &destination, sizeof (destination));
    if (retv != ip_datagram_length) {
        perror("Couldn't send all data");
        return -1;
    }

    // cleanup
    retv = close(socket_desc);
    if (retv != 0) {
        perror("Error closing socket");
        return -1;
    }

    return 0;

}

int spoof_icmp(int argc, char **argv) {
    const const char* source_address = argv[1];
    const const char* dest_address = argv[2];

    struct icmphdr icmph;
    icmph.type = ICMP_ECHO;
    icmph.code = 0;
    icmph.checksum = htons(0xf1d2);
    icmph.un.echo.id = htons(1580);
    icmph.un.echo.sequence = htons(1);

    return send_ip_datagram(source_address, dest_address,
            &icmph, sizeof(icmph), IPPROTO_ICMP);
}

int spoof_generic(int argc, char **argv) {
    const const char* source_address = argv[1];
    const const char* dest_address = argv[2];
    const const void* payload = argv[3];
    size_t payload_length = strlen(payload);
    uint8_t protocol = IPPROTO_IP;

    return send_ip_datagram(source_address, dest_address,
            payload, payload_length, protocol);
}

int mac_string_to_addr(const const char* mac_addr_string,
        uint8_t *mac_addr,
        size_t mac_addr_capacity) {
    int octets_read;
    if (mac_addr_capacity < ETH_ALEN) {
        printf("Insufficient capacity %zu for %u octets of mac address",
                mac_addr_capacity, ETH_ALEN);
        return -1;
    }

    octets_read = sscanf(mac_addr_string,
            "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &mac_addr[0], &mac_addr[1], &mac_addr[2],
            &mac_addr[3], &mac_addr[4], &mac_addr[5]);

    if (octets_read < 0) {
        perror("Error reading address");
        return -1;
    } else if (octets_read < ETH_ALEN) {
        printf("Bad address %s\n", mac_addr_string);
        return -1;
    } else {
        return 0;
    }
}

int spoof_frame(int argc, char **argv) {
    const const char* source_mac_address = argv[1];
    const const char* source_ip_address = argv[2];
    const const char* dest_mac_address = argv[3];
    const const char* dest_ip_address = argv[4];
    const const void* payload = argv[5];
    size_t payload_length = strlen(payload);

    char frame[1514];
    char *frame_data;
    struct ethhdr *eth_h;
    struct sockaddr_ll device_send_address;
    int socket_desc;
    size_t frame_capacity = sizeof(frame);
    size_t frame_length;
    size_t header_length;
    ssize_t ip_datagram_length;
    int retv;

    memset(frame, 0, frame_capacity);
    memset(&device_send_address, 0, sizeof(device_send_address));
    eth_h = (struct ethhdr *) frame;
    header_length = sizeof(struct ethhdr);

    // parse source and dest mac address
    eth_h->h_proto = htons(ETH_P_IP);
    retv = mac_string_to_addr(source_mac_address, eth_h->h_source, sizeof(eth_h->h_source));
    if (retv != 0) {
        printf("Error converting address\n");
        return -1;
    }
    retv = mac_string_to_addr(dest_mac_address, eth_h->h_dest, sizeof(eth_h->h_dest));
    if (retv != 0) {
        printf("Error converting address\n");
        return -1;
    }

    // add ip datagram to frame
    frame_data = frame + header_length;
    ip_datagram_length = create_ip_packet(frame_data, frame_capacity - header_length,
            source_ip_address, dest_ip_address,
            payload, payload_length, IPPROTO_IP);
    if (ip_datagram_length < 0) {
        printf("Error creating ip datagram\n");
        return -1;
    }
    frame_length = header_length + ip_datagram_length;

    socket_desc = socket(AF_PACKET, SOCK_RAW, ETH_P_IP);
    if (socket_desc < 0) {
        perror("Error creating socket");
        return -1;
    }

    device_send_address.sll_family = AF_PACKET;
    memcpy(device_send_address.sll_addr, eth_h->h_dest, ETH_ALEN);
    device_send_address.sll_halen = ETH_ALEN;
    device_send_address.sll_ifindex = 2;
    device_send_address.sll_protocol = ETH_P_IP;
    retv = sendto(socket_desc, frame, frame_length, 0,
            (struct sockaddr *) &device_send_address, sizeof (device_send_address));
    if (retv != frame_length) {
        perror("Couldn't send all data");
        return -1;
    }

    // cleanup
    retv = close(socket_desc);
    if (retv != 0) {
        perror("Error closing socket");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    return spoof_frame(argc, argv);
}