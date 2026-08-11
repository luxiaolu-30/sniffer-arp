#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <QString>

// Static utility class for network interface operations
class NetworkUtils
{
public:
    // Get IP address of a network interface
    static void getIP(char* local_ip, const char* eth_name);

    // Get MAC address of a network interface
    static void getMAC(char* mac, const char* eth_name);

    // Get default gateway address from /proc/net/route
    static QString getGateway();
};

#endif // NETWORK_UTILS_H
