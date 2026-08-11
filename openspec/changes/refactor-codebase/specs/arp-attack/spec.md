## ADDED Requirements

### Requirement: ARP 报文发送线程
系统 SHALL 提供一个继承自 QThread 的 ARP 报文发送线程类，使用 libnet 构造和发送 ARP 报文。

#### Scenario: 发送线程启动
- **WHEN** ARP 发送线程启动时
- **THEN** 系统 SHALL 调用 `send_pkt()` 方法执行报文发送逻辑

### Requirement: ARP 报文参数配置
系统 SHALL 允许配置 ARP 报文的发送参数，包括网络设备、操作类型、源 MAC、源 IP、目的 MAC、目的 IP、以太网目的 MAC 和以太网源 MAC。

#### Scenario: 参数设置
- **WHEN** 调用 `getParam` 方法
- **THEN** 系统 SHALL 存储所有传入参数到成员变量，包括设备名、操作码、源/目的 MAC 地址、源/目的 IP 地址、以太网层源/目的 MAC 地址

### Requirement: ARP 操作模式
系统 SHALL 支持三种 ARP 操作模式：单播应答、广播请求和广播应答。

#### Scenario: 单播应答模式 (unicast)
- **WHEN** 操作码为 `'a'`
- **THEN** 系统 SHALL 设置 ARP 操作为 `ARPOP_REPLY`，启用持续发送标志

#### Scenario: 广播请求模式 (broadcast_req)
- **WHEN** 操作码为 `'b'`
- **THEN** 系统 SHALL 将目的 MAC 清零、以太网目的 MAC 设为广播地址(0xFF)，设置 ARP 操作为 `ARPOP_REQUEST`，启用持续发送标志

#### Scenario: 广播应答模式 (broadcast)
- **WHEN** 操作码为 `'c'`
- **THEN** 系统 SHALL 将目的 MAC 清零、以太网目的 MAC 设为广播地址(0xFF)，设置 ARP 操作为 `ARPOP_REPLY`，将目的 IP 设为源 IP，启用持续发送标志

### Requirement: ARP 报文构造
系统 SHALL 使用 libnet 构造完整的 ARP 报文，包括 ARP 头和以太网头。

#### Scenario: ARP 头构造
- **WHEN** 构造 ARP 报文
- **THEN** 系统 SHALL 调用 `libnet_build_arp` 构造 ARP 头，硬件类型为 `ARPHRD_ETHER`，协议类型为 `ETHERTYPE_IP`，MAC 长度 6，协议长度 4，使用配置的操作码、源/目的 MAC 和源/目的 IP

#### Scenario: 以太网头构造
- **WHEN** ARP 头构造成功后
- **THEN** 系统 SHALL 调用 `libnet_build_ethernet` 构造以太网头，使用配置的以太网源/目的 MAC，协议类型为 `ETHERTYPE_ARP`

### Requirement: ARP 报文持续发送
系统 SHALL 在持续发送标志为 true 时循环发送 ARP 报文。

#### Scenario: 持续发送
- **WHEN** 持续发送标志为 true
- **THEN** 系统 SHALL 循环调用 `libnet_write` 发送报文，每次发送后发射 `writelog` 信号并休眠 100 毫秒

#### Scenario: 发送停止
- **WHEN** 线程被终止（`terminate`）
- **THEN** 系统 SHALL 退出发送循环，调用 `libnet_destroy` 释放 libnet 上下文

### Requirement: MAC 地址字符串转换
系统 SHALL 提供将 MAC 地址字符串（如 "AA:BB:CC:DD:EE:FF"）转换为 6 字节数组的方法。

#### Scenario: 有效 MAC 地址转换
- **WHEN** 输入长度为 17 的 MAC 地址字符串（格式 XX:XX:XX:XX:XX:XX）
- **THEN** 系统 SHALL 将每 2 个十六进制字符转换为 1 字节，填充 6 字节数组

#### Scenario: 无效 MAC 地址
- **WHEN** 输入长度不为 17
- **THEN** 系统 SHALL 返回空 QVector，不修改输出数组

### Requirement: ARP 攻击日志
系统 SHALL 在每次发送 ARP 报文时记录日志。

#### Scenario: 日志记录
- **WHEN** ARP 报文发送成功
- **THEN** 系统 SHALL 发射 `writelog` 信号，UI 层在日志列表中添加攻击开始时间、发送 IP、发送 MAC、目标 IP、目标 MAC 等信息
