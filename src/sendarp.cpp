#include "sendarp.h"
#include<QVector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void sendarp::run(){
    send_pkt();
}

sendarp::sendarp(QThread *parent) : QThread(parent)
{
}

void sendarp::getParam(char* dev,int op,unsigned char src_mac[6],char* src_ip_str,unsigned char dst_mac[6],
    char* dst_ip_str,unsigned char eth_dst_mac[6],unsigned char eth_src_mac[6])
{
    this->dev= dev;
    this->op = op;
    this->dst_ip_str = dst_ip_str;
    this->src_ip_str = src_ip_str;
    for(int i = 0; i < 6; i++)
    {
        this->src_mac[i] = src_mac[i];
        this->dst_mac[i] = dst_mac[i];
        this->eth_src_mac[i] = eth_src_mac[i];
        this->eth_dst_mac[i] = eth_dst_mac[i];
    }
    this->srcip = QString(src_ip_str);
    this->dstip = QString(dst_ip_str);
    qDebug()<<"ip and mac set success"<<endl;
    qDebug()<<"dev"<<dev<<endl;
//    qDebug()<<"op"<<op<<endl;
//    qDebug()<<"src_ip"<<src_ip_str<<endl;
//    qDebug()<<"dst_ip"<<dst_ip_str<<endl;
//    qDebug()<<"src_mac"<<src_mac<<endl;
//    qDebug()<<"dst_mac"<<dst_mac<<endl;
//    qDebug()<<"eth_src_mac"<<eth_src_mac<<endl;
//    qDebug()<<"eth_dst_mac"<<eth_dst_mac<<endl;
}

int sendarp::send_pkt()
{
    net_t = NULL;
    src_ip, dst_ip = 0;

    net_t = libnet_init(LIBNET_LINK_ADV, dev, err_buf);//初始化发送包结构
//    src_ip = libnet_name2addr4(net_t, src_ip_str, LIBNET_RESOLVE);//将字符串类型的ip转换为顺序网络字节流
//    dst_ip = libnet_name2addr4(net_t, dst_ip_str, LIBNET_RESOLVE);
    src_ip=inet_addr(src_ip_str);
    dst_ip=inet_addr(dst_ip_str);

    if(net_t == NULL)
    {
        fprintf(stderr, "libnet_init error/n");
        qDebug()<<err_buf<<endl;
        return -1;
    }
    switch (op) {
    case 'b':// request packet
        for(int i = 0; i < 6; i++)
        {
            dst_mac[i] = 0x00;
            eth_dst_mac[i] = 0xff;
        }
//      qDebug()<<"send 00:00:00:00:00:00"<<endl;
        flag = true;
        arpop = ARPOP_REQUEST;
        break;
    case 'a':
        arpop = ARPOP_REPLY;
        flag = true;
        break;
    case 'c':
        for(int i = 0; i < 6; i++)
        {
            //
            dst_mac[i] = 0x00;
            eth_dst_mac[i] = 0xff;
        }
        arpop = ARPOP_REPLY;
        dst_ip = src_ip;
        flag = true;
    }

    p_tag = libnet_build_arp(
                ARPHRD_ETHER,//hardware type ethernet
                ETHERTYPE_IP,//protocol type
                6,//mac length
                4,//protocol length
                arpop,//op type
                (u_int8_t *)src_mac,//source mac addr这里的作用是更新目的地的arp表
                (u_int8_t *)&src_ip,//source ip addr
                (u_int8_t *)dst_mac,//dest mac addr
                (u_int8_t *)&dst_ip,//dest ip  addr
                NULL,//payload
                0,//payload length
                net_t,//libnet context
                0//0 stands to build a new one
     );//构造数据包arp头
    if(p_tag == -1)
    {
        fprintf(stderr, "libnet_build_arp error/n");
        return -1;
    }

    p_tag = libnet_build_ethernet(//create ethernet header
                    (u_int8_t *)eth_dst_mac,//dest mac addr
                    (u_int8_t *)eth_src_mac,//source mac addr
                    ETHERTYPE_ARP,//protocol type
                    NULL,//payload
                    0,//payload length
                    net_t,//libnet context
                    0//0 to build a new one
    );//构造数据包ethernet头
    if(p_tag == -1)
    {
        fprintf(stderr, "libnet_build_eth error/n");
        return -1;
    }
    do{
        //send packet
        int res = libnet_write(net_t);
        if(res == -1)
        {
            fprintf(stderr, "libnet_write error\n");
            return -1;
        }
//        qDebug()<<"send over"<<endl;
        emit writelog();
        msleep(100);
    }while(flag);

    libnet_destroy(net_t);
}

QVector<unsigned char> sendarp::Qs2uc(QString strMac, unsigned char* mac)
{
//    char* qm = strMac.toLatin1().data();
     unsigned char s_mac[6]={0};
     int index=0;
     QVector<unsigned char> vecMac;
     unsigned char* p = vecMac.data();
     if (strMac.size() != 17)
        {
            return vecMac;
        }
        for (int i = 0; i < strMac.size(); i += 3)
        {
            QString num = strMac.mid(i, 2);
            bool ok = false;
            vecMac.push_back(num.toUInt(&ok, 16));
            s_mac[index]=num.toUInt(&ok, 16);
            index++;
            if (!ok)
            {
                return QVector<unsigned char>();
            }
        }


    for(int i = 0; i < 6; i++)
    {
        mac[i] = s_mac[i];
    }
        return vecMac;
}

