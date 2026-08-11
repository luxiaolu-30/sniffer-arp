/*
* Module: Capture packets from network interface and parse protocol fields
* Author: muzinan
* Refactored: global variables replaced with class member variables
*/
#include "getthread.h"
#include <pcap.h>
#include <netinet/in.h>

getthread::getthread(QThread *parent) : QThread(parent)
{
    stopped = false;
    m_protoFlag = 0;
    qRegisterMetaType<QVariant>("QVariant");
}

void getthread::set_filter(QString filter_str){
    this->filter_str = filter_str;
}

// Static callback wrapper for pcap_loop - forwards to member function
static void pcap_callback(u_char* user, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    getthread* self = reinterpret_cast<getthread*>(user);
    self->handleEthernet(nullptr, packet_header, packet_content);
}

void getthread::handleIcmp(u_char ip_header_len, const u_char* packet_content)
{
    struct icmp_header *icmp_protocol;
    icmp_protocol = (struct icmp_header *)(packet_content + 14 + 20);
    m_icmpData = *icmp_protocol;
}

void getthread::handleUdp(u_char ip_header_len, const u_char* packet_content)
{
    udp_header *udp_protocol;
    udp_protocol = (udp_header*)(packet_content + 14 + ip_header_len);
    m_udpData = *udp_protocol;

    if (ntohs(udp_protocol->udp_source_port) == 67 || ntohs(udp_protocol->udp_source_port) == 68) {
        // DHCP protocol - do not set protocol flag
    } else {
        m_protoFlag = udp;
    }
}

void getthread::handleTcp(u_char ip_header_len, const u_char* packet_content)
{
    tcp_header* tcp_protocol;
    tcp_protocol = (struct tcp_header *)(packet_content + 14 + ip_header_len);
    m_tcpData = *tcp_protocol;
}

void getthread::handleIp(u_char* argument,
    const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    struct ip_header *ip_protocol;
    u_int header_length;
    u_int offset;
    u_char tos;
    u_int16_t checksum;
    ip_protocol = (struct ip_header *)(packet_content + 14);
    checksum = ntohs(ip_protocol->ip_checksum);
    header_length = ip_protocol->ip_header_length * 4;
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);

    m_ipData = *ip_protocol;

    switch(ip_protocol->ip_protocol)
    {
        case 6:
            handleTcp(header_length, packet_content);
            m_protoFlag = tcp;
            printf("The Transport Layer Protocol is TCP\n");
            break;
        case 17:
            handleUdp(header_length, packet_content);
            printf("The Transport Layer Protocol is UDP\n");
            break;
        case 1:
            handleIcmp(header_length, packet_content);
            m_protoFlag = icmp;
            printf("The Transport Layer Protocol is ICMP\n");
            break;
        default:
            m_protoFlag = ip;
            break;
    }
}

void getthread::handleArp(u_char* argument,
    const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    struct arp_header *arp_protocol;
    arp_protocol = (struct arp_header*)(packet_content + 14);
    m_arpData = *arp_protocol;
}

void getthread::handleEthernet(u_char* argument,
    const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    u_short ethernet_type;
    struct ether_header *ethernet_protocol;
    u_char *mac_string;
    static int packet_number = 1;

    ethernet_protocol = (struct ether_header*)packet_content;
    ethernet_type = ntohs(ethernet_protocol->ether_type);

    m_etherData = *ethernet_protocol;
    printf("%04x\n", ethernet_type);

    switch(ethernet_type)
    {
        case 0x0800:
            handleIp(argument, packet_header, packet_content);
            printf("the  network layer is IP protocol \n");
            break;
        case 0x0806:
            m_protoFlag = arp;
            handleArp(argument, packet_header, packet_content);
            printf("the  network layer is ARP protocol \n");
            break;
        case 0x8035:
            printf("the  network layer is RARP protocol \n");
            break;
        default:
            break;
    }
    packet_number++;
}

void getthread::run(){
    char error_content[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;

    char * net_interface;
    net_interface = pcap_lookupdev(error_content);
    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);

    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 1, error_content);

    struct bpf_program bpf_filter;
    QByteArray str = this->filter_str.toLatin1();
    char* bpf_filter_str = str.data();

    cout << "filter" << bpf_filter_str;

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_str, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    if (pcap_datalink(pcap_handle) != DLT_EN10MB) return;

    QVariant var1;
    QVariant var2;
    QVariant var3;
    QVariant var4;
    QVariant var5;
    QVariant var6;
    stopped = false;
    while(!stopped)
    {
        // Pass 'this' as user data so the callback can access member variables
        pcap_loop(pcap_handle, 1, pcap_callback, reinterpret_cast<u_char*>(this));
        var1.setValue(m_ipData);
        var2.setValue(m_arpData);
        var3.setValue(m_tcpData);
        var4.setValue(m_udpData);
        var5.setValue(m_icmpData);
        var6.setValue(m_etherData);

        emit stringChanged(m_protoFlag, var1, var2, var3, var4, var5, var6);
        msleep(100);
    }
}

void getthread::stop()
{
    stopped = true;
    pcap_close(this->pcap_handle);
}
