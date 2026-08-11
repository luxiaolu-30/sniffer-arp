#include "network_utils.h"
#include <QDebug>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <cstdio>

void NetworkUtils::getIP(char* local_ip, const char* eth_name)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin;
    struct ifreq ifr;
    if (sock == -1) {
        qDebug() << "get mac error" << endl;
        return;
    }

    strcpy(ifr.ifr_name, eth_name);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        return;
    }
    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));

    sprintf(local_ip, "%s", inet_ntoa(sin.sin_addr));
}

void NetworkUtils::getMAC(char* mac, const char* eth_name)
{
    struct ifreq ifr;
    int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd == -1) {
        qDebug() << "get mac error" << endl;
        return;
    }
    strcpy(ifr.ifr_name, eth_name);
    if (ioctl(socketfd, SIOCGIFHWADDR, &ifr) < 0) {
        return;
    }

    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    return;
}

QString NetworkUtils::getGateway()
{
    char buff[256];
    int nl = 0;
    struct in_addr gw;
    int flgs, ref, use, metric;
    unsigned long int d, g, m;
    FILE* fp = nullptr;
    QString gatewayAddr;

    fp = fopen("/proc/net/route", "r");
    if (fp == nullptr) {
        return gatewayAddr;
    }
    nl = 0;
    memset(buff, 0, sizeof(buff));
    while (fgets(buff, sizeof(buff), fp) != nullptr) {
        if (nl) {
            int ifl = 0;
            while (buff[ifl] != ' ' && buff[ifl] != '\t' && buff[ifl] != '\0')
                ifl++;
            buff[ifl] = 0;
            if (sscanf(buff + ifl + 1, "%lx%lx%X%d%d%d%lx",
                       &d, &g, &flgs, &ref, &use, &metric, &m) != 7) {
                fclose(fp);
            }

            ifl = 0;
            gw.s_addr = g;

            if (d == 0) {
                gatewayAddr = QString(inet_ntoa(gw));
                fclose(fp);
                return gatewayAddr;
            }
        }
        nl++;
    }
    if (fp) {
        fclose(fp);
        fp = nullptr;
    }
    return gatewayAddr;
}
