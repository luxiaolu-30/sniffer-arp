# Packet Sniffer Capability

## Purpose

定义数据包嗅探功能的规格，包括数据包捕获、协议解析、信号传递和计数统计。

## Requirements

### Requirement: 数据包捕获线程
系统 SHALL 提供一个继承自 QThread 的抓包线程类，使用 libpcap 从默认网络接口捕获数据包，并按协议格式解析每个字段后通过信号传递给 UI 层。

#### Scenario: 启动抓包
- **WHEN** 用户点击"开始"按钮并设置 BPF 过滤表达式
- **THEN** 系统调用 `pcap_lookupdev` 获取默认网络接口，使用 `pcap_open_live` 打开抓包句柄（缓冲区 BUFSIZ，混杂模式 1，超时 1），编译并设置 BPF 过滤器，然后进入循环调用 `pcap_loop` 捕获数据包

#### Scenario: 停止抓包
- **WHEN** 用户点击"停止"按钮
- **THEN** 系统设置停止标志为 true，调用 `pcap_close` 关闭抓包句柄，退出捕获循环

#### Scenario: BPF 过滤器设置
- **WHEN** 用户在过滤表达式文本框中输入 BPF 表达式并启动抓包
- **THEN** 系统 SHALL 通过 `pcap_compile` 编译过滤表达式并通过 `pcap_setfilter` 应用过滤器

#### Scenario: 数据链路类型检查
- **WHEN** 抓包线程启动并打开网络接口
- **THEN** 系统 SHALL 通过 `pcap_datalink` 检查数据链路类型，若不是 `DLT_EN10MB`（以太网）则直接返回不进行捕获

### Requirement: 以太网协议解析
系统 SHALL 解析以太网帧头，提取源 MAC 地址、目的 MAC 地址和以太网类型字段，并根据以太网类型分发到上层协议解析器。

#### Scenario: IP 协议帧
- **WHEN** 以太网类型为 `0x0800`
- **THEN** 系统 SHALL 调用 IP 协议解析回调函数

#### Scenario: ARP 协议帧
- **WHEN** 以太网类型为 `0x0806`
- **THEN** 系统 SHALL 设置协议标志为 ARP，并调用 ARP 协议解析回调函数

#### Scenario: RARP 协议帧
- **WHEN** 以太网类型为 `0x8035`
- **THEN** 系统 SHALL 识别为 RARP 协议（仅日志输出，不进一步解析）

### Requirement: IP 协议解析
系统 SHALL 解析 IP 协议头，提取版本、首部长度、总长度、TOS、标识、偏移、TTL、协议类型、校验和、源 IP 和目的 IP 地址，并根据协议类型分发到传输层解析器。

#### Scenario: TCP 协议
- **WHEN** IP 协议类型字段为 6
- **THEN** 系统 SHALL 调用 TCP 协议解析回调，设置协议标志为 TCP

#### Scenario: UDP 协议
- **WHEN** IP 协议类型字段为 17
- **THEN** 系统 SHALL 调用 UDP 协议解析回调

#### Scenario: ICMP 协议
- **WHEN** IP 协议类型字段为 1
- **THEN** 系统 SHALL 调用 ICMP 协议解析回调，设置协议标志为 ICMP

#### Scenario: 其他 IP 协议
- **WHEN** IP 协议类型字段不是 6、17 或 1
- **THEN** 系统 SHALL 设置协议标志为 IP（仅网络层）

### Requirement: TCP 协议解析
系统 SHALL 解析 TCP 协议头，提取源端口、目的端口、序列号、确认号、标志位、窗口大小、校验和和紧急指针。

#### Scenario: TCP 字段提取
- **WHEN** 接收到 TCP 协议数据
- **THEN** 系统 SHALL 跳过以太网头（14 字节）和 IP 头（按首部长度计算），解析 TCP 头各字段

### Requirement: UDP 协议解析
系统 SHALL 解析 UDP 协议头，提取源端口、目的端口、长度和校验和。

#### Scenario: UDP 字段提取
- **WHEN** 接收到 UDP 协议数据
- **THEN** 系统 SHALL 跳过以太网头（14 字节）和 IP 头，解析 UDP 头各字段

#### Scenario: DHCP 协议识别
- **WHEN** UDP 源端口为 67 或 68
- **THEN** 系统 SHALL 识别为 DHCP 协议（不设置协议标志为 UDP）

### Requirement: ICMP 协议解析
系统 SHALL 解析 ICMP 协议头，提取类型、代码、校验和、标识符和序列号。

#### Scenario: ICMP 字段提取
- **WHEN** 接收到 ICMP 协议数据
- **THEN** 系统 SHALL 跳过以太网头（14 字节）和 IP 头（20 字节），解析 ICMP 头各字段

### Requirement: ARP 协议解析
系统 SHALL 解析 ARP 协议头，提取硬件类型、协议类型、硬件地址长度、协议地址长度、操作码、源以太网地址、源 IP 地址、目的以太网地址和目的 IP 地址。

#### Scenario: ARP 字段提取
- **WHEN** 接收到 ARP 协议数据
- **THEN** 系统 SHALL 跳过以太网头（14 字节），解析 ARP 头各字段

### Requirement: 数据包信号传递
系统 SHALL 在每次捕获并解析数据包后，通过 Qt 信号将协议标志和所有协议头数据（封装为 QVariant）传递给 UI 层。

#### Scenario: 信号发射
- **WHEN** `pcap_loop` 回调完成一次数据包解析
- **THEN** 系统 SHALL 发射 `stringChanged` 信号，携带 7 个参数：协议标志(int)、IP 头(QVariant)、ARP 头(QVariant)、TCP 头(QVariant)、UDP 头(QVariant)、ICMP 头(QVariant)、以太网头(QVariant)

#### Scenario: 捕获间隔
- **WHEN** 系统在捕获循环中运行
- **THEN** 每次捕获后 SHALL 休眠 100 毫秒（`msleep(100)`）再继续下一次捕获

### Requirement: 数据包计数统计
系统 SHALL 维护数据包计数器，统计总数及各协议（IP、ARP、TCP、UDP、ICMP）的数量。

#### Scenario: TCP/UDP/ICMP 计数
- **WHEN** 捕获到 TCP、UDP 或 ICMP 数据包
- **THEN** 系统 SHALL 同时递增对应协议计数和 IP 协议计数（因为 TCP/UDP/ICMP 承载于 IP 之上）

#### Scenario: 计数器清零
- **WHEN** 用户点击"清空嗅探"按钮
- **THEN** 系统 SHALL 将所有计数器重置为 0 并更新 UI 显示
