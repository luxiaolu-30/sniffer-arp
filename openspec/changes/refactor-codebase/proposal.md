## Why

当前项目代码存在严重的架构和工程质量问题：`mainwindow.h` 中直接 `#include "ip_info.cpp"`（将源文件当头文件包含）、`getthread.cpp` 使用全局变量传递协议解析数据、`MainWindow` 类承担了 UI、网络 I/O、协议解析、攻击逻辑等全部职责（上帝类）、硬编码路径（如 `/home/muzinan/list.txt`）、旧式 signal/slot 连接、裸指针和 `const_cast` 滥用、缺少错误处理等。这些问题导致代码难以维护、难以测试、存在潜在内存安全和线程安全问题。需要在不改变任何功能的前提下对代码进行结构性重构。

## What Changes

- **消除 `.cpp` 直接包含**：将 `ip_info.cpp` 中的 `ipinfo` 类移入正确的头文件 `include/ip_info.h`，`mainwindow.h` 改为 `#include "ip_info.h"`
- **消除全局变量**：将 `getthread.cpp` 中的全局协议数据变量（`etherData`、`ipData`、`arpData`、`tcpData`、`udpData`、`icmpData`、`protoc_flag`）封装为类的成员变量或通过回调参数传递
- **拆分 `MainWindow` 上帝类**：将网络接口工具函数（`get_ip`、`get_mac`）、IP 地理位置查询逻辑（`getWeatherInfo`、`parseJson`、`onReplied`）从 `MainWindow` 中提取到独立的工具/服务类中
- **协议头定义独立化**：将以太网、IP、ARP、TCP、UDP、ICMP 等协议头结构体和枚举从 `getthread.h` 中提取到独立的 `include/protocol_headers.h` 中，供多个模块复用
- **消除硬编码路径**：将 `/home/muzinan/list.txt` 等硬编码路径替换为可配置的相对路径或运行时参数
- **现代化 signal/slot 连接**：将旧式 `SIGNAL()`/`SLOT()` 宏连接替换为函数指针式连接
- **改进内存管理**：将 `icmpflood*`、`smurf*` 等裸指针替换为智能指针（`std::unique_ptr`），消除 `const_cast` 滥用
- **统一代码风格**：统一命名规范（类名 PascalCase、方法 camelCase、成员变量 `m_` 前缀），添加 `namespace` 隔离
- **改进错误处理**：为 libpcap/libnet 操作添加错误检查和日志输出，替换空的 `catch` 块和静默失败

## Capabilities

### New Capabilities

- `packet-sniffer`: 数据包捕获与多协议解析（Ethernet/IP/ARP/TCP/UDP/ICMP），包括 BPF 过滤、协议字段提取、数据包计数统计
- `arp-attack`: ARP 攻击功能，包括单播/广播 ARP 请求与应答发送、ARP 欺骗报文构造
- `host-scanner`: 主机发现功能，通过 nmap 扫描 IP 段并读取 `/proc/net/arp` 获取局域网主机列表
- `icmp-flood`: ICMP Flood 攻击，多线程发送 ICMP Echo 报文泛洪
- `smurf-attack`: Smurf 攻击，向广播地址发送源 IP 伪造的 UDP 报文
- `ip-geolocation`: IP 地理位置查询，通过 HTTP API 查询 IP 归属地信息并解析 JSON 响应
- `network-interface`: 网络接口工具，获取本机网卡列表、IP 地址、MAC 地址、网关地址
- `main-gui`: 主窗口 GUI，集成所有功能的图形化操作界面

### Modified Capabilities

（无——本项目尚无现有规格定义，所有能力均为首次规格化）

## Impact

- **源代码文件**：`include/` 和 `src/` 下所有文件均受影响，文件结构将重新组织
- **新增文件**：`include/protocol_headers.h`、`include/ip_info.h`、`include/network_utils.h` 等
- **构建配置**：`muzinan.pro` 的 SOURCES/HEADERS 列表需同步更新
- **依赖库**：不改变 libpcap、libnet、Qt5 的依赖关系
- **功能行为**：所有现有功能（嗅探、ARP 攻击、主机扫描、ICMP Flood、Smurf、IP 查询）的行为保持完全不变
- **平台**：仍为 Linux 平台（依赖 `/proc/net/arp`、`/proc/net/route`、POSIX socket API）
