#ifndef SPOOF_H
#define SPOOF_H

int send_ip_datagram(const const char* source_address,
        const const char* dest_address,
        const const void* payload,
        size_t payload_length,
        uint8_t protocol);

#endif /* SPOOF_H */

