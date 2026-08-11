# Host Scanner Capability

## Purpose

定义主机扫描功能的规格，包括 ARP 扫描线程、IP 段扫描、ARP 表读取和主机列表显示。

## Requirements

### Requirement: ARP 主机扫描线程
系统 SHALL 提供一个继承自 QThread 的 ARP 扫描线程类，用于发现局域网内的活动主机。

#### Scenario: 线程启动
- **WHEN** ARP 扫描线程启动时
- **THEN** 系统 SHALL 调用 `reflush_ips()` 方法执行主机发现逻辑

### Requirement: IP 段扫描
系统 SHALL 支持通过 nmap 工具扫描指定 IP 段内的活动主机。

#### Scenario: 指定 IP 段扫描
- **WHEN** 用户在 IP 段输入框中输入 IP 段并点击"刷新"按钮
- **THEN** 系统 SHALL 设置扫描 IP 段参数，构造 `nmap -sP <ip段> -T5` 命令并通过 `system()` 执行

#### Scenario: 未指定 IP 段
- **WHEN** IP 段输入框为空
- **THEN** 系统 SHALL 直接读取系统 ARP 表，不执行 nmap 扫描

### Requirement: ARP 表读取
系统 SHALL 读取 `/proc/net/arp` 文件获取系统 ARP 表中的主机列表。

#### Scenario: 读取 ARP 表
- **WHEN** 执行 `reflush_ips()` 方法
- **THEN** 系统 SHALL 执行 `cat /proc/net/arp` 命令将 ARP 表写入临时文件，然后逐行读取文件内容

#### Scenario: 跳过表头
- **WHEN** 读取 ARP 表文件
- **THEN** 系统 SHALL 跳过第一行表头，从第二行开始逐行解析主机信息

### Requirement: 主机信息传递
系统 SHALL 将每行 ARP 表记录通过信号传递给 UI 层。

#### Scenario: 逐行发射信号
- **WHEN** 读取到一行有效的 ARP 表记录
- **THEN** 系统 SHALL 发射 `get_host(QString)` 信号，携带原始行文本，并休眠 100 毫秒后继续读取下一行

#### Scenario: ARP 表格式
- **WHEN** UI 层接收到主机信息
- **THEN** 每行记录 SHALL 包含 6 个字段：IP 地址、硬件类型、标志、MAC 地址、掩码、网络设备名（以空格分隔）

### Requirement: 主机列表显示
系统 SHALL 在 UI 的 hosts 表格中显示扫描到的主机信息。

#### Scenario: 添加主机行
- **WHEN** UI 层接收到 `get_host` 信号
- **THEN** 系统 SHALL 在 hosts 表格中新增一行，按空格分隔各字段填入对应列（IP、HW_type、Flags、HW_address、Mask、Device），并将解析后的数据存入 `hosts_vector`

#### Scenario: 点击主机行填充攻击参数
- **WHEN** 用户点击 hosts 表格中的某一行
- **THEN** 系统 SHALL 将该行的 IP 地址填入源 IP 输入框，MAC 地址填入源 MAC 输入框

#### Scenario: 清空主机列表
- **WHEN** 用户点击"清空"按钮
- **THEN** 系统 SHALL 移除 hosts 表格中的所有行

#### Scenario: 默认刷新
- **WHEN** 用户点击"默认"按钮
- **THEN** 系统 SHALL 调用 `reflush_ips()` 读取系统 ARP 表（不执行 nmap 扫描）
