/*
* Module: Capture packets from network interface and parse protocol fields
* Author: muzinan
*/
#ifndef GETTHREAD_H
#define GETTHREAD_H

#include <QThread>
#include <QVariant>
#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include "protocol_headers.h"

class getthread : public QThread
{
    Q_OBJECT
public:
    void stop();
    explicit getthread(QThread *parent = 0);
    volatile bool stopped;
    void set_filter(QString filter_str);
private:
    QString filter_str;
    pcap_t* pcap_handle; // libpcap handle

    // Protocol data members (replacing former global variables)
    ether_header m_etherData;
    ip_header m_ipData;
    arp_header m_arpData;
    tcp_header m_tcpData;
    udp_header m_udpData;
    icmp_header m_icmpData;
    int m_protoFlag;

    // Protocol callback handlers (using member variables instead of globals)
    void handleIcmp(u_char ip_header_len, const u_char* packet_content);
    void handleUdp(u_char ip_header_len, const u_char* packet_content);
    void handleTcp(u_char ip_header_len, const u_char* packet_content);
    void handleIp(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
    void handleArp(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
    void handleEthernet(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);

protected:
    void run();

signals:
    void stringChanged(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant);

public slots:
};

#endif // GETTHREAD_H
