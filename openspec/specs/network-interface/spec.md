# Network Interface Capability

## Purpose

定义网络接口功能的规格，包括设备列表获取、默认接口信息、网卡 IP/MAC 获取和网关地址获取。

## Requirements

### Requirement: 网络设备列表获取
系统 SHALL 获取本机所有可用的网络设备列表。

#### Scenario: 枚举设备
- **WHEN** 用户点击"获取所有设备"按钮
- **THEN** 系统 SHALL 调用 `pcap_findalldevs` 枚举所有网络设备，将每个设备名称添加到设备下拉列表中，最后调用 `pcap_freealldevs` 释放设备列表

### Requirement: 默认网络接口信息
系统 SHALL 在初始化时获取默认网络接口的 IP 地址和子网掩码。

#### Scenario: 获取默认接口信息
- **WHEN** 主窗口初始化数据时
- **THEN** 系统 SHALL 调用 `pcap_lookupdev` 获取默认网络接口名，调用 `pcap_lookupnet` 获取网络地址和掩码，将 IP 和掩码转换为字符串形式存储

#### Scenario: 查看网络接口信息
- **WHEN** 用户触发"网络接口"菜单项
- **THEN** 系统 SHALL 弹出对话框显示网络接口名、网络 IP 地址和网络掩码地址

### Requirement: 网卡 IP 地址获取
系统 SHALL 通过 POSIX ioctl 接口获取指定网络设备的 IP 地址。

#### Scenario: 获取 IP
- **WHEN** 调用 `get_ip` 方法并传入网络设备名
- **THEN** 系统 SHALL 创建 SOCK_DGRAM 套接字，通过 `ioctl(SIOCGIFADDR)` 获取设备 IP 地址，转换为字符串格式返回

#### Scenario: 套接字创建失败
- **WHEN** 套接字创建失败
- **THEN** 系统 SHALL 输出调试日志"get mac error"并返回

### Requirement: 网卡 MAC 地址获取
系统 SHALL 通过 POSIX ioctl 接口获取指定网络设备的 MAC 地址。

#### Scenario: 获取 MAC
- **WHEN** 调用 `get_mac` 方法并传入网络设备名
- **THEN** 系统 SHALL 创建 SOCK_DGRAM 套接字，通过 `ioctl(SIOCGIFHWADDR)` 获取设备 MAC 地址，格式化为 `xx:xx:xx:xx:xx:xx` 字符串返回

#### Scenario: 套接字创建失败
- **WHEN** 套接字创建失败
- **THEN** 系统 SHALL 输出调试日志"get mac error"并返回

### Requirement: 网关地址获取
系统 SHALL 通过读取 `/proc/net/route` 获取默认网关地址。

#### Scenario: 获取默认网关
- **WHEN** 用户点击"网关"按钮
- **THEN** 系统 SHALL 打开 `/proc/net/route` 文件，逐行解析路由表，找到目标地址为 0 的路由项，将其网关地址转换为字符串填入源 IP 输入框

### Requirement: 设备选择与应用
系统 SHALL 允许用户从设备列表中选择网络设备并应用到当前会话。

#### Scenario: 选择设备
- **WHEN** 用户从设备下拉列表中选择设备并点击"使用"按钮
- **THEN** 系统 SHALL 设置当前使用的设备名，在攻击设备标签中显示设备名，获取并显示该设备的 MAC 地址和 IP 地址

#### Scenario: 设置扫描 IP 段
- **WHEN** 用户在选择设备时已在 IP 段输入框中输入内容
- **THEN** 系统 SHALL 将输入的 IP 段设置到 ARP 扫描线程中

### Requirement: 本地 MAC 地址快速填充
系统 SHALL 提供快捷按钮将当前选中设备的 MAC 地址填入源 MAC 输入框。

#### Scenario: 填充本地 MAC
- **WHEN** 用户点击"本地 MAC"按钮
- **THEN** 系统 SHALL 获取当前选中设备的 MAC 地址并填入源 MAC 输入框
