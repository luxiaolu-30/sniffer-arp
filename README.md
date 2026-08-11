# sniffer-arp

基于 Qt C++ 的网络数据包嗅探与分析工具，同时集成了 ARP 相关攻击功能（仅用于学习和授权测试目的）。

---

## 功能概述

- **网络数据包嗅探**：捕获并分析经过本机网卡的网络数据包
- **ARP 攻击工具**：ARP 欺骗、ARP 泛洪、Smurf 攻击、ICMP  Flood 等
- **GUI 界面**：基于 Qt 的图形化操作界面，支持实时查看嗅探结果

---

## 快速启动

> 从零到运行，只需 3 步。

### 1. 安装依赖

```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y qt5-default libpcap-dev libnet-dev build-essential nmap

# Fedora
sudo dnf install -y qt5-qtbase-devel libpcap-devel libnet-devel gcc-c++ nmap
```

### 2. 编译构建

```bash
git clone https://github.com/<your-username>/sniffer-arp.git
cd sniffer-arp
qmake muzinan.pro
make -j$(nproc)
```

### 3. 运行

```bash
sudo ./muzinan
```

> **为什么需要 sudo？** 抓包 (`libpcap`) 和原始套接字操作需要 `CAP_NET_RAW` 权限。如果不想每次使用 `sudo`，可以授予二进制文件 capabilities：
>
> ```bash
> sudo setcap cap_net_raw+ep ./muzinan
> ```

### 基本操作

| 操作 | 步骤 |
|------|------|
| **开始嗅探** | 启动程序 → 点击"开始" → 实时查看数据包列表与协议统计 |
| **过滤流量** | 在过滤框输入 BPF 表达式（如 `tcp port 80`、`host 192.168.1.1`）→ 点击"开始" |
| **主机扫描** | 输入 IP 段（如 `192.168.1.0/24`）→ 点击"刷新" → 查看发现的主机 |
| **ARP 攻击** | 从主机列表点击目标 → 选择攻击类型（ARP 欺骗 / ARP 泛洪）→ 点击启动 |
| **ICMP Flood** | 填写源/目的 IP → 设置线程数 → 点击 ICMP Flood 按钮 |
| **Smurf 攻击** | 填写目的 IP → 点击 Smurf 按钮 |
| **IP 查询** | 输入 IP 地址 → 点击查询 → 查看归属地信息 |

---

## 相关技术

| 功能 | 依赖库 |
|------|--------|
| 网络数据包嗅探 | [libpcap](https://www.tcpdump.org/) |
| 网络数据包发送 | [libnet](https://github.com/libnet/libnet) |
| GUI 界面 | Qt 5 (Widgets + Network) |

---

## 项目结构

```
sniffer-arp/
├── src/                        # 源代码
│   ├── main.cpp                    # 程序入口
│   ├── mainwindow.cpp              # 主窗口逻辑
│   ├── mainwindow.ui               # 主窗口 UI 设计
│   ├── getthread.cpp               # 数据包捕获线程
│   ├── arpattack.cpp               # ARP 扫描/攻击实现
│   ├── sendarp.cpp                 # ARP 报文发送
│   ├── ip_info.cpp                 # IP 信息解析（类已迁移至 ip_info.h，保留为空）
│   ├── icmpflood.cpp               # ICMP Flood 攻击
│   ├── smurf.cpp                   # Smurf 攻击
│   ├── network_utils.cpp           # 网络工具（IP/MAC 获取）
│   └── ip_location_service.cpp     # IP 归属地查询服务
│
├── include/                    # 头文件
│   ├── mainwindow.h             # 主窗口
│   ├── getthread.h              # 抓包线程
│   ├── arpattack.h              # ARP 扫描线程
│   ├── sendarp.h                # ARP 发送线程
│   ├── icmpflood.h              # ICMP Flood
│   ├── smurf.h                  # Smurf 攻击
│   ├── protocol_headers.h       # 协议头结构体（以太网/IP/TCP/UDP/ICMP/ARP）
│   ├── ip_info.h                # IP 信息数据类
│   ├── network_utils.h          # 网络工具静态方法
│   └── ip_location_service.h    # IP 归属地查询服务
│
├── img/                        # 界面截图资源
├── resources.qrc               # Qt 资源文件
├── muzinan.pro                 # Qt Creator 项目文件
└── list.txt                    # 辅助文件（ARP 攻击目标列表）
```

---

## 构建与运行

> Linux 平台的快速编译与运行方式见上方 [快速启动](#快速启动) 章节。

### Windows (MinGW)

1. 安装 [Qt](https://www.qt.io/download)（含 MinGW 工具链）
2. 下载并编译 [libpcap](https://www.winpcap.org/devel.htm)（或 WinPcap Developer's Pack）
3. 下载并编译 [libnet](https://github.com/libnet/libnet)
4. 在 `muzinan.pro` 中更新 `LIBS` 路径指向本地库位置

```bash
# Qt Creator 中打开 muzinan.pro → 配置 Kit → 构建并运行
```

### 注意事项

- `muzinan.pro` 中的 `LIBS` 配置需要根据本地 libpcap/libnet 的安装位置进行调整。默认配置 `-lpcap -lnet` 适用于 Linux 系统级安装。
- Windows 下需手动指定库路径，例如：
  ```
  LIBS += -L"C:/path/to/libpcap" -lpcap
  LIBS += -L"C:/path/to/libnet" -lnet
  ```

---

## 界面展示

![主界面](img/yy.png)
![截图1](img/10001.png)
![截图2](img/10002.png)

---

## ⚠️ 法律与道德声明

本项目中的 ARP 攻击、ICMP Flood、Smurf 攻击等功能**仅用于网络安全学习和授权测试目的**。使用这些功能对未经授权的网络或系统进行攻击属于违法行为。使用者需自行承担因滥用本项目代码而产生的一切法律责任。

---

## 许可证

本项目仅用于学习交流，请遵守当地法律法规。
