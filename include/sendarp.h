#ifndef SEND_ARP_PACKET_H
#define SEND_ARP_PACKET_H
#include <QThread>
#include <libnet.h>
#include<iostream>
#include<QDebug>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <QString>
class sendarp:public QThread
{
    Q_OBJECT
public:
    explicit sendarp(QThread *parent = 0);
    int send_pkt();
    QVector<unsigned char> Qs2uc(QString MAC, unsigned char* mac);
    void getParam(char dev[10],int op,unsigned char src_mac[6],char* src_ip_str,unsigned char dst_mac[6],
            char* dst_ip_str,unsigned char eth_dst_mac[6],unsigned char eth_src_mac[6]);
    uint8_t ASCII_To_Hex(char number);
    bool flag = false;
private:
    libnet_t *net_t;
    char err_buf[LIBNET_ERRBUF_SIZE];
    unsigned long src_ip, dst_ip;
    libnet_ptag_t p_tag;

    char* dev;
    int op;
    unsigned char src_mac[6];
    char* src_ip_str;
    unsigned char dst_mac[6];
    char* dst_ip_str=const_cast<char*>("0.0.0.0");
    unsigned char eth_dst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};//目的mac
    unsigned char eth_src_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};//源mac 只能使用真实mac
    int arpop = 1;

    QString srcip,dstip;
protected:
    void run();
signals:
    void writelog();
};

#endif // SEND_ARP_PACKET_H
