#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <unistd.h>

int sockoptval = 1;

int main(int argc, char **argv) {
    struct sockaddr_in destination;

    int fd = 0;
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (fd == -1) {
        perror("Could not create socket");
        return -1;
    }

    char datagram[4096];
    char *data;

    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *) datagram;

    destination.sin_family = AF_INET;
    destination.sin_port = htons(39640);
    destination.sin_addr.s_addr = htons(1);

    destination.sin_family = AF_INET;
    destination.sin_port = htons(80);
    // www.google.com
    destination.sin_addr.s_addr = inet_addr("172.217.3.164");

    data = datagram + sizeof (struct iphdr) + sizeof (struct tcphdr);
    const const char* payload = "payload";
    strncpy(data, payload, sizeof (datagram) - sizeof (struct iphdr) - sizeof (struct tcphdr) - 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(payload);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = htons(1);
    iph->daddr = destination.sin_addr.s_addr;

    int retv;
    retv = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &sockoptval, sizeof (int));
    if (retv != 0) {
        perror("Couldn't set headers included option");
        return -1;
    }

    retv = sendto(fd, datagram, iph->tot_len, 0, (struct sockaddr *) &destination, sizeof (destination));
    if (retv != iph->tot_len) {
        perror("Couldn't send all data");
        return -1;
    }

    retv = close(fd);
    if (retv != 0) {
        perror("Error closing socket");
        return -1;
    }

    return 0;
}
