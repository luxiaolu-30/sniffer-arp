#include "arpattack.h"
#include <pcap.h>
#include <netinet/in.h>
#include <iostream>
#include <QDebug>
#include <QMessageBox>
#include <stdlib.h>
#include <QFile>
#include <QTextStream>
#include <string>
using namespace std;
arpAttack::arpAttack(QThread *parent) : QThread(parent)
{

}
void arpAttack::run(){
    reflush_ips();
}
void arpAttack::setscan_ips(char* ips){
    this->scan_ips=ips;
    scan_flag=true;
}
void arpAttack::reflush_ips()
{
    if(scan_flag){
        string ips=this->scan_ips;
        string cmd_line="nmap -sP "+ips+" -T5";
        system(cmd_line.c_str());
        qDebug()<<"scan_ips over"<<endl;
    }
    system("cat /proc/net/arp > /home/muzinan/list.txt");
    QFile file("/home/muzinan/list.txt");
    if(!file.open(QIODevice::ReadOnly)){
        qDebug()<<"open file failed"<<endl;
    };
    QTextStream in(&file);
    QString linetemp=in.readLine();
    QString line=in.readLine();
    while(!line.isNull()){
        qDebug()<<line<<endl;
        emit get_host(line);
        msleep(100);
        line=in.readLine();
    }

    file.close();
    return;
}
