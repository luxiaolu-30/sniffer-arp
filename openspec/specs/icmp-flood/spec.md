# ICMP Flood Capability

## Purpose

定义 ICMP Flood 攻击功能的规格，包括多线程发送、libnet 上下文初始化、报文构造和线程同步。

## Requirements

### Requirement: ICMP Flood 攻击
系统 SHALL 提供 ICMP Flood 攻击功能，使用 libnet 和 pthread 多线程发送大量 ICMP Echo 请求报文。

#### Scenario: 攻击初始化
- **WHEN** 用户点击 ICMP Flood 按钮并提供源 IP、目的 IP、ICMP ID、起始序列号、结束序列号和线程数
- **THEN** 系统 SHALL 创建 `icmpflood` 对象，解析所有参数并初始化攻击

### Requirement: 多线程 ICMP 发送
系统 SHALL 使用指定数量的线程并行发送 ICMP Echo 报文。

#### Scenario: 线程创建
- **WHEN** ICMP Flood 攻击启动
- **THEN** 系统 SHALL 创建指定数量的 pthread 线程，每个线程分配一个 `thread_arg` 结构体，包含共享的 libnet 上下文、源/目的 IP、ICMP ID 和序列号范围

#### Scenario: 序列号范围分配
- **WHEN** 创建多个线程
- **THEN** 系统 SHALL 将序列号范围（起始到结束）均匀分配到各线程，每个线程负责 `[start + i * range, start + (i+1) * range - 1]` 范围

#### Scenario: 线程数验证
- **WHEN** 用户指定的线程数小于 1 或大于 256
- **THEN** 系统 SHALL 输出错误信息（但不中止执行）

### Requirement: libnet 上下文初始化
系统 SHALL 创建 libnet 原始套接字上下文用于 ICMP 报文发送。

#### Scenario: 上下文创建成功
- **WHEN** ICMP Flood 初始化
- **THEN** 系统 SHALL 调用 `libnet_init(LIBNET_RAW4, NULL, NULL)` 创建上下文，若失败则输出错误并退出

### Requirement: ICMP 报文构造
系统 SHALL 使用 libnet 构造 ICMP Echo 请求报文和 IP 头。

#### Scenario: ICMP 头构造
- **WHEN** 线程函数执行
- **THEN** 系统 SHALL 调用 `libnet_build_icmpv4_echo` 构造 ICMP Echo 报文，类型为 `ICMP_ECHO`，代码为 0，校验和为 0（自动计算），使用指定的 ICMP ID

#### Scenario: IP 头构造
- **WHEN** ICMP 头构造成功后
- **THEN** 系统 SHALL 调用 `libnet_build_ipv4` 构造 IP 头，总长度为 `LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H`，TTL 64，协议 `IPPROTO_ICMP`，使用指定的源/目的 IP

### Requirement: ICMP 报文发送
系统 SHALL 在每个线程中循环发送 ICMP 报文。

#### Scenario: 序列号循环发送
- **WHEN** 线程开始发送
- **THEN** 系统 SHALL 从 `seq_start` 到 `seq_end` 循环调用 `libnet_write` 发送报文，每次发送后休眠 5 毫秒

#### Scenario: 发送失败处理
- **WHEN** `libnet_write` 返回 -1
- **THEN** 系统 SHALL 输出错误信息并退出当前线程

### Requirement: 线程同步
系统 SHALL 等待所有发送线程完成后释放资源。

#### Scenario: 线程等待
- **WHEN** 所有线程创建完成
- **THEN** 系统 SHALL 对每个线程调用 `pthread_join` 等待其完成

#### Scenario: 资源释放
- **WHEN** 所有线程完成
- **THEN** 系统 SHALL 调用 `libnet_destroy` 释放 libnet 上下文

### Requirement: 本地 IP 快速填充
系统 SHALL 提供快捷按钮将本地网卡 IP 填入 ICMP 源 IP 输入框。

#### Scenario: 填充本地 IP
- **WHEN** 用户点击"localhost"按钮
- **THEN** 系统 SHALL 将当前选中网卡的 IP 地址填入 ICMP 源 IP 输入框
