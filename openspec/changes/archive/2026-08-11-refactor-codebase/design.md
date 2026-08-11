## Context

sniffer-arp 是一个基于 Qt5 C++ 的网络数据包嗅探与 ARP 攻击工具，依赖 libpcap（抓包）和 libnet（发包），运行于 Linux 平台。当前代码由 8 个源文件和 6 个头文件组成，所有逻辑集中在 `MainWindow` 类中，存在架构耦合、代码质量低下等问题。项目无自动化测试，无 CI/CD，构建方式为 qmake + make。

当前代码结构：
```
include/  → mainwindow.h, getthread.h, arpattack.h, sendarp.h, icmpflood.h, smurf.h
src/      → main.cpp, mainwindow.cpp, getthread.cpp, arpattack.cpp, sendarp.cpp,
             ip_info.cpp, icmpflood.cpp, smurf.cpp, mainwindow.ui
```

关键问题：
- `mainwindow.h` 第 11 行 `#include "ip_info.cpp"` 直接包含源文件
- `getthread.cpp` 使用 7 个全局变量（`etherData`、`ipData`、`arpData`、`tcpData`、`udpData`、`icmpData`、`protoc_flag`）在线程回调和类成员间传递数据
- `MainWindow` 类有 30+ 方法，混合 UI 逻辑、网络 I/O、协议解析、攻击控制、HTTP 请求、JSON 解析
- 硬编码路径 `/home/muzinan/list.txt`
- 旧式 `SIGNAL()/SLOT()` 宏连接
- `icmpflood*`、`smurf*` 裸指针无智能管理

## Goals / Non-Goals

**Goals:**
- 消除 `#include "ip_info.cpp"` 的源文件包含反模式
- 消除 `getthread.cpp` 中的全局变量，改为类成员封装
- 将 `MainWindow` 的非 UI 职责提取到独立类中（网络工具、IP 查询服务）
- 将协议头结构体独立到 `include/protocol_headers.h`，消除跨模块重复定义风险
- 消除硬编码路径，改为可配置参数
- 将旧式 signal/slot 连接全部替换为函数指针式
- 将裸指针替换为智能指针
- 统一代码风格和命名规范
- 保持所有功能行为完全不变

**Non-Goals:**
- 不新增任何功能特性
- 不修改 UI 布局或交互方式（`mainwindow.ui` 不变）
- 不更换依赖库（仍使用 libpcap、libnet、Qt5）
- 不添加跨平台支持（仍为 Linux 专用）
- 不添加自动化测试框架（本次重构范围外）
- 不修改 `list.txt` 辅助文件的格式

## Decisions

### 1. 协议头定义独立文件

**决策**：创建 `include/protocol_headers.h`，将 `getthread.h` 中的 `ether_header`、`ip_header`、`arp_header`、`tcp_header`、`udp_header`、`icmp_header` 结构体和协议枚举移入其中。

**理由**：当前这些结构体定义在 `getthread.h` 中，但 `mainwindow.h` 也需要引用（通过 `changeString` 方法解析 QVariant）。独立后可被多个模块直接包含，避免间接依赖抓包线程头文件。同时将 `Q_DECLARE_METATYPE` 声明也移入，确保 QVariant 注册一致性。

**替代方案**：保持现状，在 `mainwindow.h` 中 `#include "getthread.h"` 间接获取——但这使得 UI 类与抓包线程实现强耦合。

### 2. `ipinfo` 类从头文件化

**决策**：将 `src/ip_info.cpp` 中的 `ipinfo` 类定义移到 `include/ip_info.h`，`src/ip_info.cpp` 保留为空或删除（类定义全在内联头文件中）。`mainwindow.h` 改为 `#include "ip_info.h"`。

**理由**：消除 `#include "ip_info.cpp"` 反模式。`ipinfo` 是纯数据类（12 个 QString 成员），适合定义为内联头文件类，无需单独 .cpp 实现。

**替代方案**：将 `ipinfo` 改为 .h/.cpp 分离——但该类无逻辑方法，分离反而增加不必要的文件。

### 3. `MainWindow` 职责拆分

**决策**：提取以下独立类：
- `NetworkUtils`（`include/network_utils.h`）：封装 `get_ip()`、`get_mac()`、网关获取逻辑，均为静态方法
- `IpLocationService`（`include/ip_location_service.h`）：封装 `getWeatherInfo()`、`parseJson()`、`onReplied()` 及 `QNetworkAccessManager` 管理

`MainWindow` 保留 UI 控制和信号路由职责，通过组合方式持有 `IpLocationService`。

**理由**：`get_ip`/`get_mac` 是纯网络工具函数，与 UI 无关；IP 查询是独立的 HTTP 服务逻辑。提取后 `MainWindow` 从 30+ 方法减少到 ~20 方法，职责清晰。

**替代方案**：完全 MVC 化（分离 Model/View/Controller）——但改动过大，超出"保持功能不变"的约束。

### 4. 消除 `getthread` 全局变量

**决策**：将 `getthread.cpp` 中的全局变量（`etherData`、`ipData`、`arpData`、`tcpData`、`udpData`、`icmpData`、`protoc_flag`）改为 `getthread` 类的私有成员变量。回调函数改为接受 `getthread*` 指针参数（通过 `pcap_loop` 的 `user` 参数传递），直接写入对象的成员变量。

**理由**：全局变量导致线程安全问题（多个 `getthread` 实例共享状态）和可测试性问题。通过 `pcap_loop` 的 `u_char* user` 参数传递 `this` 指针是 libpcap 的标准模式。

**替代方案**：使用 thread_local——但不解决可测试性和封装性问题。

### 5. 硬编码路径参数化

**决策**：将 `arpattack.cpp` 中的 `/home/muzinan/list.txt` 替换为可配置的成员变量 `m_arpFilePath`，默认值为项目目录下的 `list.txt`。`MainWindow` 在初始化时设置路径。

**理由**：当前硬编码路径使项目无法在其他用户/机器上运行。改为相对路径后提升可移植性。

### 6. 现代 signal/slot 连接

**决策**：将所有 `connect(sender, SIGNAL(...), receiver, SLOT(...))` 替换为 `connect(sender, &SenderClass::signalName, receiver, &ReceiverClass::slotName)` 函数指针式连接。

**理由**：函数指针式连接在编译期进行类型检查，避免运行时信号名拼写错误。这是 Qt5 的推荐实践。

### 7. 智能指针管理

**决策**：`MainWindow` 中的 `icmpflood* icmpf` 和 `smurf* smf` 替换为 `std::unique_ptr<icmpflood>` 和 `std::unique_ptr<smurf>`。

**理由**：当前代码中 `new` 创建的对象从未 `delete`，存在内存泄漏。智能指针确保自动释放。

### 8. 文件结构重组

**决策**：重构后文件结构：
```
include/
├── protocol_headers.h    # 协议头结构体 + 枚举 + Q_DECLARE_METATYPE
├── ip_info.h             # ipinfo 数据类
├── network_utils.h       # 网络工具静态方法
├── ip_location_service.h # IP 地理位置查询服务
├── mainwindow.h          # 主窗口（精简后）
├── getthread.h           # 抓包线程（仅类声明）
├── arpattack.h           # ARP 扫描线程
├── sendarp.h             # ARP 报文发送线程
├── icmpflood.h           # ICMP Flood
└── smurf.h               # Smurf 攻击
src/
├── main.cpp
├── mainwindow.cpp        # 主窗口实现（精简后）
├── mainwindow.ui         # UI 文件（不变）
├── getthread.cpp         # 抓包线程实现（全局变量消除）
├── arpattack.cpp         # ARP 扫描实现（路径参数化）
├── sendarp.cpp           # ARP 发送实现
├── icmpflood.cpp         # ICMP Flood 实现
├── smurf.cpp             # Smurf 实现
└── ip_info.cpp           # 保留为空或删除
```

## Risks / Trade-offs

- **[重构引入行为变化]** → 逐模块重构，每次改动后对照原始行为验证；保持 `mainwindow.ui` 不变确保 UI 交互一致
- **[全局变量消除可能影响回调时序]** → `pcap_loop` 的 `user` 参数传递 `this` 是 libpcap 标准模式，行为等价；回调仍为同步调用，无线程竞争变化
- **[智能指针改变对象生命周期]** → `icmpflood` 和 `smurf` 当前创建后永不释放，改用 `unique_ptr` 后每次按钮点击会先释放旧对象再创建新对象，行为上等价（攻击是单次触发）
- **[头文件重组导致编译依赖变化]** → 同步更新 `muzinan.pro` 的 HEADERS/SOURCES 列表，确保 qmake 识别所有文件
- **[无自动化测试难以验证]** → 手动验证清单：抓包功能、各协议解析、ARP 攻击、主机扫描、ICMP Flood、Smurf、IP 查询逐项确认
