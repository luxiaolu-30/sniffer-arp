#ifndef ARPATTACK_H
#define ARPATTACK_H
#include <QThread>
#include <QVariant>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <iostream>
#include <QString>

class arpAttack:public QThread
{
    Q_OBJECT
public:
    explicit arpAttack(QThread *parent = 0);
    char* scan_ips;
    //
    void setscan_ips(char* ips);
    void reflush_ips();
    void setArpFilePath(const QString& path) { m_arpFilePath = path; }
signals:
    void get_host(QString);

private:
    bool scan_flag=false;
    QString m_arpFilePath;  // Configurable path for ARP table output (replaces hardcoded path)
protected:
    void run();


};

#endif // ARPATTACK_H
