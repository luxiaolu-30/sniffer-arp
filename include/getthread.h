/*
* 本模块的功能：从网卡中得到数据并按照协议格式解析每个字段的内容
* 作者：muzinan
*/
#ifndef GETTHREAD_H
#define GETTHREAD_H

#include <QThread>
#include <QVariant>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <iostream>

enum{
    tcp,udp,icmp,arp,ip
};
//ether
struct  ether_header
{
    u_int8_t ether_dhost[6];   //目的以太网地址
    u_int8_t ether_shost[6];   //源以太网地址
    u_int16_t ether_type;       //以太网类型

};
//icmp 协议格式
struct icmp_header
{
   u_int8_t icmp_type;/*ICMP类型*/
   u_int8_t icmp_code;/*ICMP代码*/
   u_int16_t icmp_checksum;/*校验和*/
   u_int16_t icmp_id_11iiuuwweennttaaoo;/*标识符*/
   u_int16_t icmp_sequence;/*序列号*/
};
//ip
struct ip_header{
    #ifdef WORDS_BIGENDIAN
    u_int8_t  ip_version:4,    //ip协议版本
              ip_header_length:4;  //ip协议首部长度
    #else
    u_int8_t  ip_header_length:4,
              ip_version:4;
    #endif
    u_int8_t  ip_tos;           //tos服务质量
    u_int16_t ip_length;    //总长度
    u_int16_t ip_id;    //标识
    u_int16_t ip_off;    //偏移
    u_int8_t  ip_tt1;    //生存时间
    u_int8_t  ip_protocol;    //协议类型
    u_int16_t ip_checksum;   //校验和
    struct in_addr ip_source_address;  //源ip地址
    struct in_addr ip_destination_address; //目的ip地址
};

//TCP 协议格式
struct tcp_header
{
    u_int16_t tcp_source_port;  /*源端口*/
    u_int16_t tcp_destination_port;/*目的端口*/
    u_int32_t tcp_acknowledgement;  /*序列号*/
    u_int32_t tcp_ack ; /*确认号*/
    #ifdef wORDS_BIGENDIAN
    u_int8_t tcp_offset : 4,        /*偏移*/
            tcp_reserved : 4 ;      /*保留*/
    #else
    u_int8_t tcp_reserved : 4,
    tcp_offset : 4 ;
    /*偏移*/
    #endif
    u_int8_t tcp_flags ;        /*标志*/
    u_int16_t tcp_windows ;        /*窗口大小*/
    u_int16_t tcp_checksum;     /*校验和*/
    u_int16_t tcp_urgent_pointer;   /*紧急指针*/
};
//udp 协议格式
struct udp_header
{
    u_int16_t udp_source_port;  /*源端口*/
    u_int16_t udp_destination_port;/*目的端口*/
    u_int16_t udp_checksum;     /*校验和*/
    u_int16_t udp_length;   /*长度*/
};
//arp协议格式
struct arp_header{
    u_int16_t arp_hardware_type;  //硬件地址类型
    u_int16_t arp_protocol_type;    //协议地址类型
    u_int8_t arp_hardware_length;    //硬件地址长度
    u_int8_t arp_protocol_length;    //协议地址长度
    u_int16_t arp_operation_code ;   //操作类型
    u_int8_t arp_source_ethernet_address[6]; //源以太网地址
    struct in_addr arp_source_ip_address; //源ip地址
    u_int8_t arp_destination_ethernet_address [6];   //目的以太网地址
    struct in_addr arp_destination_ip_address; //目的ip地址
};

Q_DECLARE_METATYPE(ether_header)
Q_DECLARE_METATYPE(icmp_header)
Q_DECLARE_METATYPE(ip_header)
Q_DECLARE_METATYPE(tcp_header)
Q_DECLARE_METATYPE(udp_header)
Q_DECLARE_METATYPE(arp_header)

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
    pcap_t* pcap_handle; //libpcap句柄
protected:
    void run();

signals:
    void stringChanged(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant);

public slots:
};

#endif // GETTHREAD_H
