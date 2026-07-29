/*
* 本模块的功能：从网卡中得到数据并按照协议格式解析每个字段的内容
* 作者：muzinan
*/
#include "getthread.h"
#include <pcap.h>
#include <netinet/in.h>

getthread::getthread(QThread *parent) : QThread(parent)
{
    stopped = false;
    qRegisterMetaType<QVariant>("QVariant");
}

void getthread::set_filter(QString filter_str){
    this->filter_str=filter_str;
}

ether_header etherData;
ip_header ipData;
arp_header arpData;
tcp_header tcpData;
udp_header udpData;
icmp_header icmpData;
//DHCP_HEADER dhcpData;
int protoc_flag;
void icmp_protocol_packet_callback(u_char ip_header_len,const u_char* packet_content)
{
    struct icmp_header *icmp_protocol;/*icmp 协议数据变量*/
    /*获得icmp协议数据内容，应该跳过以太网头和IP头部分*/
    icmp_protocol = (struct icmp_header *) (packet_content+14+20) ;
    icmpData=*icmp_protocol;

}
//callback functions
void udp_protocol_packet_callback(u_char ip_header_len,const u_char* packet_content)
{
    udp_header *udp_protocol;
    udp_protocol=(udp_header*)(packet_content+14+ip_header_len);
    udpData=*udp_protocol;

    if(ntohs(udp_protocol->udp_source_port)==67 ||ntohs(udp_protocol->udp_source_port)==68 )
    {
        // DHCP protocol
    }else{
        protoc_flag=udp;
    }
}
void tcp_protocol_packet_callback(u_char ip_header_len,const u_char* packet_content)
{
    tcp_header* tcp_protocol;
    /*获得TCP协议数据内容，应该跳过以太网头和IP头部分*/
    tcp_protocol = (struct tcp_header *) (packet_content+14+ip_header_len) ;
    tcpData=*tcp_protocol;

}
void ip_protocol_packet_callback(u_char* argument,
const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
    struct ip_header *ip_protocol;
    //长度
    u_int header_length;
    //偏移
    u_int offset;
    //服务质量
    u_char tos ;
    //校验和
    u_int16_t checksum;
    ip_protocol = (struct ip_header * ) (packet_content+14) ;
    /*获得iP协议数据内容，去掉以太网头*/
    checksum = ntohs (ip_protocol->ip_checksum) ;
    header_length = ip_protocol->ip_header_length*4 ;
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);

    ipData=*ip_protocol;

    switch(ip_protocol->ip_protocol)
    {
        case 6:
        tcp_protocol_packet_callback(header_length , packet_content);
        protoc_flag=tcp;
        printf("The Transport Layer Protocol is TCP\n");
        break;
        case 17:
        udp_protocol_packet_callback (header_length , packet_content);
        /*如果判断上层协议是UDP协议，就调用分析UDP协议的函数。注意此时的参数传递*/
        printf("The Transport Layer Protocol is UDP\n");
        break;
        case 1:
        icmp_protocol_packet_callback(header_length , packet_content);
        protoc_flag=icmp;
        printf("The Transport Layer Protocol is ICMP\n");
        break;
        default:
        protoc_flag=ip;
        break;
    }

}
void arp_protocol_packet_callback(u_char* argument,
const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
    struct arp_header *arp_protocol;  //arp协议变量
    //跳过前14字节的以太网数据部分 获得ARP协议数据
    arp_protocol=(struct arp_header*)(packet_content+14);
    arpData=*arp_protocol;

}

void ethernet_protocol_packet_callback(u_char* argument,
const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
    //以太网类型
    u_short ethernet_type;
    //以太网协议格式
    struct ether_header *ethernet_protocol;
    //以太网地址
    u_char *mac_string;
    //表示捕获数据包的个数
    static int packet_number=1;

    //将数据包缓存进行类型的强制转换，使之变成以太网协议格式的数据类型
    ethernet_protocol=(struct ether_header*)packet_content;

    //获得以太网类型
    ethernet_type=ntohs(ethernet_protocol->ether_type);


    etherData=*ethernet_protocol;
    //输出以太网类型
    printf("%04x\n",ethernet_type);

    switch(ethernet_type)
    {
        case 0x0800:
        ip_protocol_packet_callback(argument,packet_header,packet_content);
        printf("the  network layer is IP protocol \n");
        break;
        case 0x0806:
        protoc_flag=arp;
           //如果以太网类型是0x0806 表示上层协议是ARP协议，调用ARP协议分析函数
        arp_protocol_packet_callback(argument,packet_header,packet_content);
        printf("the  network layer is ARP protocol \n");
        break;
        case 0x8035: printf("the  network layer is RARP protocol \n");
        break;
        default:
        break;
    }
    packet_number++;
}

void getthread::run(){
    char error_content[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net_mask;//mask address
    bpf_u_int32 net_ip;//ip address

    char * net_interface; //network interface
    net_interface=pcap_lookupdev(error_content); //get interface
    pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content);

    pcap_handle=pcap_open_live(net_interface,BUFSIZ,1,1,error_content);

    struct bpf_program bpf_filter;
    QByteArray str = this->filter_str.toLatin1();
    char*bpf_filter_str=str.data();

    cout<<"filter"<<bpf_filter_str;

    pcap_compile(pcap_handle,&bpf_filter,bpf_filter_str,0,net_ip);
    pcap_setfilter(pcap_handle,&bpf_filter);

    if(pcap_datalink(pcap_handle)!=DLT_EN10MB)  return;

    QVariant var1;
    QVariant var2;
    QVariant var3;
    QVariant var4;
    QVariant var5;
    QVariant var6;
    //QVariant var7;
    stopped = false;
    while(!stopped)
    {
        pcap_loop(pcap_handle,1,ethernet_protocol_packet_callback,NULL);
        var1.setValue(ipData);
        var2.setValue(arpData);
        var3.setValue(tcpData);
        var4.setValue(udpData);
        var5.setValue(icmpData);
        var6.setValue(etherData);

        emit stringChanged(protoc_flag,var1,var2,var3,var4,var5,var6);
        msleep(100);
    }

}

void getthread::stop()
{
    stopped = true;
    pcap_close(this->pcap_handle);
}
