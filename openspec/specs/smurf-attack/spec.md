# Smurf Attack Capability

## Purpose

定义 Smurf 攻击功能的规格，包括多线程 UDP 发送、原始套接字创建和报文构造。

## Requirements

### Requirement: Smurf 攻击
系统 SHALL 提供 Smurf 攻击功能，使用原始套接字和 pthread 多线程向广播地址发送源 IP 伪造的 UDP 报文。

#### Scenario: 攻击初始化
- **WHEN** 用户点击 Smurf 攻击按钮并提供目的 IP
- **THEN** 系统 SHALL 创建 `smurf` 对象，启动多线程发送攻击报文

### Requirement: 多线程 UDP 发送
系统 SHALL 使用 10 个线程并行发送 Smurf 攻击报文。

#### Scenario: 线程创建
- **WHEN** Smurf 攻击启动
- **THEN** 系统 SHALL 创建 10 个 pthread 线程，每个线程执行 `generate_smurf` 函数

#### Scenario: 线程等待
- **WHEN** 所有线程创建完成
- **THEN** 系统 SHALL 对每个线程调用 `pthread_join` 等待其完成

### Requirement: 原始套接字创建
系统 SHALL 为每个线程创建原始套接字用于发送伪造报文。

#### Scenario: 套接字创建
- **WHEN** 线程函数执行
- **THEN** 系统 SHALL 调用 `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` 创建原始套接字，若失败则输出错误并返回

### Requirement: Smurf 报文构造
系统 SHALL 构造 IP 头和 UDP 头组成的 Smurf 攻击报文，源 IP 设为目标 IP，目的 IP 设为广播地址。

#### Scenario: IP 头构造
- **WHEN** 构造 Smurf 报文
- **THEN** 系统 SHALL 设置 IP 头：IHL=5，版本=4，TTL=255，协议=IPPROTO_UDP，源地址=目标 IP，目的地址=0xFFFFFFFF（广播）

#### Scenario: UDP 头构造
- **WHEN** IP 头构造完成后
- **THEN** 系统 SHALL 设置 UDP 头：源端口=7，目的端口=7，长度=sizeof(udphdr)，校验和=0

### Requirement: Smurf 报文持续发送
系统 SHALL 在每个线程中无限循环发送 Smurf 报文。

#### Scenario: 持续发送
- **WHEN** 报文构造完成
- **THEN** 系统 SHALL 无限循环调用 `sendto` 向目标地址发送报文，发送失败时输出错误信息但继续循环
