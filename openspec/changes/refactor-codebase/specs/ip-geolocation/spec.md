## ADDED Requirements

### Requirement: IP 地理位置查询
系统 SHALL 通过 HTTP API 查询 IP 地址的地理位置信息，并将结果解析显示在 UI 中。

#### Scenario: 发起查询
- **WHEN** 用户在 IP 查询输入框中输入 IP 地址并点击查询按钮
- **THEN** 系统 SHALL 构造 API 请求 URL `https://apis.tianapi.com/ipquery/index?key=<apikey>&ip=<ip>`，通过 `QNetworkAccessManager` 发送 GET 请求

### Requirement: HTTP 响应处理
系统 SHALL 处理 HTTP 响应，根据状态码决定是否解析 JSON 数据。

#### Scenario: 请求成功
- **WHEN** HTTP 响应状态码为 200 且无错误
- **THEN** 系统 SHALL 读取响应体并调用 JSON 解析方法

#### Scenario: 请求失败
- **WHEN** HTTP 响应有错误或状态码不为 200
- **THEN** 系统 SHALL 输出调试日志并弹出警告对话框提示"请求数据失败"

### Requirement: JSON 数据解析
系统 SHALL 解析 API 返回的 JSON 数据，提取 IP 归属地信息。

#### Scenario: JSON 解析成功
- **WHEN** JSON 文档解析成功且 `msg` 字段包含 "success"
- **THEN** 系统 SHALL 从 `result` 对象中提取以下字段：IP、洲、国家、省份、城市、区县、ISP、区域编码、国家编码、国家英文名、纬度、经度

#### Scenario: JSON 解析失败
- **WHEN** JSON 文档解析出错
- **THEN** 系统 SHALL 输出错误日志并返回

#### Scenario: API 返回失败
- **WHEN** JSON 中 `msg` 字段不包含 "success"
- **THEN** 系统 SHALL 弹出警告对话框提示"请求数据失败"

### Requirement: 查询结果显示
系统 SHALL 将解析后的 IP 归属地信息显示在 UI 的对应输入框中。

#### Scenario: 填充结果字段
- **WHEN** JSON 解析成功并提取所有字段
- **THEN** 系统 SHALL 将 IP、洲、国家、国家编码、国家英文名、区县、城市、ISP、区域编码、纬度、经度、省份分别填入 UI 对应的只读输入框中
