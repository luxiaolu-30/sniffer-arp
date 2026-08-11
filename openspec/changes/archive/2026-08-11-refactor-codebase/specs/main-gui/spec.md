## ADDED Requirements

### Requirement: 主窗口初始化
系统 SHALL 创建固定大小（900x800）的主窗口，设置窗口标题和图标，初始化 UI 组件和数据。

#### Scenario: 窗口创建
- **WHEN** 应用程序启动
- **THEN** 系统 SHALL 创建 `MainWindow` 实例，设置窗口大小为 900x800（不可调整），窗口标题为 "one-eye@muzinan"，窗口图标为 `:/new/imgs/img/10001.png`

#### Scenario: 定时器启动
- **WHEN** 主窗口初始化
- **THEN** 系统 SHALL 启动 1 秒间隔的定时器，用于更新界面时间显示

#### Scenario: 信号连接初始化
- **WHEN** 主窗口初始化
- **THEN** 系统 SHALL 连接抓包线程的 `stringChanged` 信号到 `changeString` 槽，连接 ARP 扫描线程的 `get_host` 信号到 `changeHost` 槽，连接 ARP 发送线程的 `writelog` 信号到 `writelog` 槽，创建 `QNetworkAccessManager` 并连接其 `finished` 信号到 `onReplied` 槽

### Requirement: 数据包列表表格
系统 SHALL 在主界面的数据包表格中显示捕获的数据包摘要信息。

#### Scenario: 表格初始化
- **WHEN** UI 初始化
- **THEN** 系统 SHALL 设置数据包表格为 4 列（Source、Destination、length、Protocol），单行选择模式，每列宽度 150 像素

#### Scenario: 添加数据包行
- **WHEN** 接收到新的数据包信号
- **THEN** 系统 SHALL 在表格中新增一行，根据协议类型填入源地址、目的地址、长度和协议名称

#### Scenario: 数据包详情查看
- **WHEN** 用户点击数据包表格中的某一行
- **THEN** 系统 SHALL 在详情列表中显示该数据包的以太网层、网络层和传输层详细信息，包括 MAC 地址、IP 地址、端口、序列号、校验和等字段

### Requirement: 协议统计显示
系统 SHALL 在 UI 中实时显示各协议的数据包计数。

#### Scenario: 更新计数
- **WHEN** 捕获到新数据包
- **THEN** 系统 SHALL 递增对应的协议计数器并更新 UI 中的总数、IP、ARP、TCP、UDP、ICMP 计数显示

### Requirement: 主机列表表格
系统 SHALL 在主界面显示扫描到的主机列表。

#### Scenario: 表格初始化
- **WHEN** UI 初始化
- **THEN** 系统 SHALL 设置主机表格为 6 列（IP address、HW_type、Flags、HW_address、Mask、Device），单行选择模式

### Requirement: 时间显示
系统 SHALL 在界面上实时显示当前日期时间。

#### Scenario: 定时更新时间
- **WHEN** 定时器触发（每秒一次）
- **THEN** 系统 SHALL 获取当前日期时间，格式化为 "yyyy.MM.dd hh:mm:ss.zzz ddd" 格式并更新时间标签

### Requirement: 自定义按钮样式
系统 SHALL 使用自定义渐变样式渲染平面按钮。

#### Scenario: 渐变按钮渲染
- **WHEN** 渲染 Flat 风格的按钮
- **THEN** 系统 SHALL 使用 `QProxyStyle` 子类绘制从红色(170,0,0)到橙色(255,170,0)的线性渐变背景，圆角半径 5 像素

### Requirement: 数据包保存功能
系统 SHALL 提供保存捕获数据包的菜单项。

#### Scenario: 保存对话框
- **WHEN** 用户点击"保存"菜单项
- **THEN** 系统 SHALL 弹出确认对话框询问"save packets?"，用户选择 Save 时输出保存日志

### Requirement: MAC 地址格式转换工具
系统 SHALL 提供在无分隔符 MAC 字符串和带冒号分隔 MAC 字符串之间转换的工具函数。

#### Scenario: 无分隔符转带分隔符
- **WHEN** 输入长度不小于 12 的无分隔符 MAC 字符串（如 "AABBCCDDEEFF"）
- **THEN** 系统 SHALL 每 2 个字符插入一个冒号，返回 "AA:BB:CC:DD:EE:FF" 格式的字符串

#### Scenario: MAC 字节数组转字符串
- **WHEN** 输入 6 字节的 MAC 地址数组
- **THEN** 系统 SHALL 将每个字节转换为 2 位十六进制字符串，拼接为无分隔符的 12 字符字符串

### Requirement: 日志显示
系统 SHALL 在日志列表中显示 ARP 攻击操作日志。

#### Scenario: ARP 攻击日志
- **WHEN** ARP 报文发送线程发射 `writelog` 信号
- **THEN** 系统 SHALL 在日志列表中添加攻击开始标记、当前时间戳、发送 IP、发送 MAC、目标 IP、目标 MAC 和攻击结束标记

#### Scenario: 清空日志
- **WHEN** 用户点击"清空日志"按钮
- **THEN** 系统 SHALL 清空日志列表中的所有条目
