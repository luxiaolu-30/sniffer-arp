# sniffer-arp

基于 Qt C++ 的网络数据包嗅探与分析工具，同时集成了 ARP 相关攻击功能（仅用于学习和授权测试目的）。

---

## 功能概述

- **网络数据包嗅探**：捕获并分析经过本机网卡的网络数据包
- **ARP 攻击工具**：ARP 欺骗、ARP 泛洪、Smurf 攻击、ICMP  Flood 等
- **GUI 界面**：基于 Qt 的图形化操作界面，支持实时查看嗅探结果

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
│   ├── arpattack.cpp               # ARP 攻击实现
│   ├── sendarp.cpp                 # ARP 报文发送
│   ├── ip_info.cpp                 # IP 信息解析
│   ├── icmpflood.cpp               # ICMP Flood 攻击
│   └── smurf.cpp                   # Smurf 攻击
│
├── include/                    # 头文件
│   ├── mainwindow.h
│   ├── getthread.h
│   ├── arpattack.h
│   ├── sendarp.h
│   ├── icmpflood.h
│   └── smurf.h
│
├── img/                        # 界面截图资源
├── resources.qrc               # Qt 资源文件
├── muzinan.pro                 # Qt Creator 项目文件
└── list.txt                    # 辅助文件
```

---

## 构建与运行

### 依赖安装

#### Linux (Ubuntu/Debian)

```bash
sudo apt-get install libpcap-dev libnet-dev qt5-default build-essential
```

#### Linux (Fedora)

```bash
sudo dnf install libpcap-devel libnet-devel qt5-qtbase-devel gcc-c++
```

#### Windows (MinGW)

1. 安装 [Qt](https://www.qt.io/download)（含 MinGW 工具链）
2. 下载并编译 [libpcap](https://www.winpcap.org/devel.htm)（或 WinPcap Developer's Pack）
3. 下载并编译 [libnet](https://github.com/libnet/libnet)
4. 在 `muzinan.pro` 中更新 `LIBS` 路径指向本地库位置

### 编译

```bash
# 使用 Qt Creator
# 打开 muzinan.pro → 配置构建 → 构建并运行

# 或使用命令行
qmake muzinan.pro
make
```

> **注意**：`muzinan.pro` 中的 `LIBS` 配置需要根据本地 libpcap/libnet 的安装位置进行调整。默认配置 `-lpcap -lnet` 适用于 Linux 系统级安装。

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
