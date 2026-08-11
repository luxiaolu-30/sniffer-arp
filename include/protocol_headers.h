#ifndef PROTOCOL_HEADERS_H
#define PROTOCOL_HEADERS_H

#include <QVariant>
#include <arpa/inet.h>
#include <stdint.h>

// Protocol type enumeration
enum ProtoType {
    tcp, udp, icmp, arp, ip
};

// Ethernet header
struct ether_header
{
    u_int8_t ether_dhost[6];   // Destination MAC address
    u_int8_t ether_shost[6];   // Source MAC address
    u_int16_t ether_type;       // Ethernet type
};

// ICMP header
struct icmp_header
{
    u_int8_t icmp_type;        // ICMP type
    u_int8_t icmp_code;        // ICMP code
    u_int16_t icmp_checksum;   // Checksum
    u_int16_t icmp_id_11iiuuwweennttaaoo; // Identifier
    u_int16_t icmp_sequence;   // Sequence number
};

// IP header
struct ip_header {
    #ifdef WORDS_BIGENDIAN
    u_int8_t  ip_version:4,    // IP protocol version
              ip_header_length:4;  // IP header length
    #else
    u_int8_t  ip_header_length:4,
              ip_version:4;
    #endif
    u_int8_t  ip_tos;           // Type of service
    u_int16_t ip_length;        // Total length
    u_int16_t ip_id;            // Identification
    u_int16_t ip_off;           // Fragment offset
    u_int8_t  ip_tt1;           // Time to live
    u_int8_t  ip_protocol;      // Protocol type
    u_int16_t ip_checksum;      // Checksum
    struct in_addr ip_source_address;        // Source IP address
    struct in_addr ip_destination_address;   // Destination IP address
};

// TCP header
struct tcp_header
{
    u_int16_t tcp_source_port;        // Source port
    u_int16_t tcp_destination_port;   // Destination port
    u_int32_t tcp_acknowledgement;    // Sequence number
    u_int32_t tcp_ack;                // Acknowledgement number
    #ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset : 4,          // Offset
            tcp_reserved : 4;         // Reserved
    #else
    u_int8_t tcp_reserved : 4,
    tcp_offset : 4;                   // Offset
    #endif
    u_int8_t tcp_flags;               // Flags
    u_int16_t tcp_windows;            // Window size
    u_int16_t tcp_checksum;           // Checksum
    u_int16_t tcp_urgent_pointer;     // Urgent pointer
};

// UDP header
struct udp_header
{
    u_int16_t udp_source_port;        // Source port
    u_int16_t udp_destination_port;   // Destination port
    u_int16_t udp_checksum;           // Checksum
    u_int16_t udp_length;             // Length
};

// ARP header
struct arp_header {
    u_int16_t arp_hardware_type;                   // Hardware address type
    u_int16_t arp_protocol_type;                    // Protocol address type
    u_int8_t arp_hardware_length;                   // Hardware address length
    u_int8_t arp_protocol_length;                   // Protocol address length
    u_int16_t arp_operation_code;                   // Operation type
    u_int8_t arp_source_ethernet_address[6];        // Source Ethernet address
    struct in_addr arp_source_ip_address;           // Source IP address
    u_int8_t arp_destination_ethernet_address[6];   // Destination Ethernet address
    struct in_addr arp_destination_ip_address;      // Destination IP address
};

Q_DECLARE_METATYPE(ether_header)
Q_DECLARE_METATYPE(icmp_header)
Q_DECLARE_METATYPE(ip_header)
Q_DECLARE_METATYPE(tcp_header)
Q_DECLARE_METATYPE(udp_header)
Q_DECLARE_METATYPE(arp_header)

#endif // PROTOCOL_HEADERS_H
