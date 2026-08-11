## 1. 协议头定义独立化

- [x] 1.1 创建 `include/protocol_headers.h`，将 `getthread.h` 中的 `ether_header`、`ip_header`、`arp_header`、`tcp_header`、`udp_header`、`icmp_header` 结构体定义移入
- [x] 1.2 将协议枚举（`tcp`、`udp`、`icmp`、`arp`、`ip`）从 `getthread.h` 移入 `include/protocol_headers.h`
- [x] 1.3 将 `Q_DECLARE_METATYPE` 声明从 `getthread.h` 移入 `include/protocol_headers.h`
- [x] 1.4 修改 `getthread.h`，移除已迁移的结构体和枚举定义，改为 `#include "protocol_headers.h"`
- [x] 1.5 修改 `mainwindow.h`，确保通过 `#include "getthread.h"` 间接或直接 `#include "protocol_headers.h"` 获取协议头定义

## 2. ipinfo 类头文件化

- [x] 2.1 创建 `include/ip_info.h`，将 `src/ip_info.cpp` 中的 `ipinfo` 类定义移入（纯头文件，内联实现）
- [x] 2.2 修改 `mainwindow.h`，将 `#include "ip_info.cpp"` 替换为 `#include "ip_info.h"`
- [x] 2.3 清空 `src/ip_info.cpp` 内容（保留空文件或从构建中移除）

## 3. 网络工具类提取

- [x] 3.1 创建 `include/network_utils.h`，定义 `NetworkUtils` 类，包含静态方法 `getIP()`、`getMAC()`、`getGateway()`
- [x] 3.2 将 `mainwindow.cpp` 中的 `get_ip()`、`get_mac()`、网关获取逻辑（`on_btn_src_ip_gateway_clicked` 中的路由表解析）迁移到 `NetworkUtils`
- [x] 3.3 在 `MainWindow` 中将原有调用改为 `NetworkUtils::getIP()`、`NetworkUtils::getMAC()`、`NetworkUtils::getGateway()` 调用

## 4. IP 查询服务类提取

- [x] 4.1 创建 `include/ip_location_service.h`，定义 `IpLocationService` 类（继承 QObject），包含 `queryIpInfo()`、`parseJson()`、`onReplied()` 方法和 `QNetworkAccessManager*` 成员
- [x] 4.2 将 `mainwindow.cpp` 中的 `getWeatherInfo()`、`parseJson()`、`onReplied()` 方法迁移到 `IpLocationService`
- [x] 4.3 在 `IpLocationService` 中定义 `ipInfoReady(ipinfo)` 信号，解析完成后发射
- [x] 4.4 在 `MainWindow` 中持有 `IpLocationService*` 成员，连接其信号到 UI 更新槽
- [x] 4.5 修改 `on_btn_q_query_clicked()` 调用 `IpLocationService::queryIpInfo()` 替代直接调用

## 5. getthread 全局变量消除

- [x] 5.1 将 `getthread.cpp` 中的全局变量（`etherData`、`ipData`、`arpData`、`tcpData`、`udpData`、`icmpData`、`protoc_flag`）改为 `getthread` 类的私有成员变量
- [x] 5.2 修改所有协议回调函数签名，增加 `getthread*` 参数（通过 `pcap_loop` 的 `user` 参数传递 `this` 指针）
- [x] 5.3 修改 `ethernet_protocol_packet_callback`、`ip_protocol_packet_callback`、`tcp_protocol_packet_callback`、`udp_protocol_packet_callback`、`icmp_protocol_packet_callback`、`arp_protocol_packet_callback` 使其写入对象成员变量而非全局变量
- [x] 5.4 修改 `getthread::run()` 中的 `pcap_loop` 调用，将 `this` 作为 `user` 参数传入
- [x] 5.5 修改 `run()` 中读取数据并发射信号的部分，改为读取成员变量

## 6. arpattack 硬编码路径修复

- [x] 6.1 在 `arpAttack` 类中添加 `m_arpFilePath` 成员变量，默认值为 `"list.txt"`（相对路径）
- [x] 6.2 添加 `setArpFilePath(const QString& path)` 设置方法
- [x] 6.3 修改 `reflush_ips()` 中的 `system("cat /proc/net/arp > /home/muzinan/list.txt")` 为使用 `m_arpFilePath`
- [x] 6.4 修改 `QFile` 打开路径为 `m_arpFilePath`

## 7. sendarp 代码改进

- [x] 7.1 修改 `sendarp.h` 中的 `getParam` 参数类型，使用 `const char*` 替代 `char*` 减少不必要的 `const_cast`（保留兼容性，聚焦 bug 修复）
- [x] 7.2 修复 `send_pkt()` 中 `src_ip, dst_ip = 0;` 的逗号表达式 bug（改为 `src_ip = 0; dst_ip = 0;`）
- [x] 7.3 添加 `libnet_init` 失败时的 `libnet_destroy` 清理

## 8. MainWindow 精简与现代化

- [x] 8.1 从 `MainWindow` 中移除已迁移到 `NetworkUtils` 和 `IpLocationService` 的方法和成员
- [x] 8.2 将 `icmpflood* icmpf` 和 `smurf* smf` 替换为 `std::unique_ptr<icmpflood>` 和 `std::unique_ptr<smurf>`
- [x] 8.3 修改 `on_btn_icmpflood_clicked()` 和 `on_btn_smurf_start_clicked()` 使用 `std::make_unique` 创建对象
- [x] 8.4 将 `mainwindow.cpp` 中所有旧式 `connect(sender, SIGNAL(...), receiver, SLOT(...))` 替换为函数指针式连接
- [x] 8.5 移除 `mainwindow.cpp` 中多余的 `#include`（已迁移到其他文件的依赖）
- [x] 8.6 统一 `Packet_Info` 和 `count_info` 结构体命名风格（添加注释说明字段含义）

## 9. 构建配置更新

- [x] 9.1 在 `muzinan.pro` 的 HEADERS 列表中添加 `include/protocol_headers.h`、`include/ip_info.h`、`include/network_utils.h`、`include/ip_location_service.h`
- [x] 9.2 在 `muzinan.pro` 的 SOURCES 列表中添加 `src/network_utils.cpp`、`src/ip_location_service.cpp`
- [x] 9.3 验证 `muzinan.pro` 中 SOURCES 和 HEADERS 列表与实际文件一致

## 10. 验证

- [ ] 10.1 执行 `qmake muzinan.pro && make` 验证编译通过
- [ ] 10.2 验证数据包嗅探功能：启动抓包、设置 BPF 过滤、停止抓包、清空列表
- [ ] 10.3 验证协议解析：确认 TCP、UDP、ICMP、ARP、IP 数据包的字段解析正确显示
- [ ] 10.4 验证数据包计数统计：确认各协议计数正确递增和清零
- [ ] 10.5 验证 ARP 攻击功能：单播/广播模式切换、MAC 地址转换、日志记录
- [ ] 10.6 验证主机扫描功能：nmap 扫描、ARP 表读取、主机列表显示和点击填充
- [ ] 10.7 验证 ICMP Flood 功能：参数配置、多线程发送
- [ ] 10.8 验证 Smurf 攻击功能：目标 IP 设置、报文发送
- [ ] 10.9 验证 IP 地理位置查询：HTTP 请求发送、JSON 解析、结果字段填充
- [ ] 10.10 验证网络接口功能：设备列表获取、IP/MAC 获取、网关获取
