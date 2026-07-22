# Minecraft 服务器状态查询工具

一个轻量级的 Minecraft Java 版服务器状态查询工具，包含 DNS 解析、服务器 Ping 和一个演示 Web 界面。

## 项目结构

```
.
├── mc_pinger.py      # Minecraft 服务器 Ping 核心模块
├── dns.py            # DNS 查询模块（支持 SRV 记录解析）
├── web.py            # Web 服务入口
└── templates/
    └── index.html    # 前端查询页面
```

## 功能
- **SRV 记录解析** - 支持 `_minecraft._tcp` SRV 记录自动解析
- **完整的 Minecraft 协议** - 握手、状态查询、Ping 延迟测量
- **重试机制** - 自动重试失败的连接和 DNS 查询
- **Web 界面** - 响应式设计，支持历史记录
- **聊天组件解析** - 支持 Minecraft 颜色代码和样式

## 快速开始

### 需要的

- 只需要完整的现代 python 环境即可

### 使用示例

```python
from mc_pinger import MinecraftPinger

# 查询服务器
pinger = MinecraftPinger("mc.hypixel.net", timeout=5.0)
result = pinger.query()

if result["success"]:
    print(f"版本: {result['version_name']}")
    print(f"玩家: {result['online_players']}/{result['max_players']}")
    print(f"延迟: {result['ping']} ms")
else:
    print(f"查询失败: {result['error']}")
```

### 启动 Web 服务

```bash
python web.py
```

访问 `http://localhost:5000` 使用 Web 界面。

## API 文档

### MinecraftPinger

```python
MinecraftPinger(
    host: str,                    # 服务器地址
    port: int = 25565,            # 端口号
    protocol_version: int = 775,  # 协议版本 （通过抓26.1客户端的包）
    timeout: float = 5.0,         # 超时时间（秒）
    retries: int = 2,             # 重试次数
    enable_ping: bool = True,     # 是否测量延迟
    enable_srv: bool = True       # 是否启用 SRV 解析
)
```

#### 方法

| 方法 | 说明 |
|------|------|
| `query()` | 执行完整查询，返回 `Dict[str, Any]` |
| `query_simple()` | 简化查询，失败返回 `None` |
| `get_status_string()` | 获取格式化的状态字符串 |

#### 返回数据结构（示例）

```python
{
    "success": True,
    "version_name": "1.21",
    "protocol": 775,
    "online_players": 42,
    "max_players": 100,
    "player_sample": ["Player1", "Player2"],
    "description": "Welcome to the server",
    "description_raw": {"text": "Welcome..."},
    "favicon": "data:image/png;base64,...",
    "ping": 42  # 毫秒（启用 enable_ping 时）
}
```

### DNSQuery

```python
DNSQuery(
    dns_servers: List[str] = None,  # DNS 服务器列表
    timeout: float = 5.0,           # 超时时间
    max_retries: int = 3,           # 重试次数
    cache_size: int = 128,          # 缓存大小
    cache_ttl: int = 300            # 缓存 TTL（秒）
)
```

#### 查询记录类型

| 常量 | 值 | 说明 |
|------|-----|------|
| `TYPE_A` | 1 | IPv4 地址 |
| `TYPE_AAAA` | 28 | IPv6 地址 |
| `TYPE_SRV` | 33 | 服务记录 |
| `TYPE_TXT` | 16 | 文本记录 |
| `TYPE_MX` | 15 | 邮件交换记录 |

## 配置

### Web 服务配置

编辑 `web.py` 中的配置：

```python
HOST = '0.0.0.0'    # 监听地址
PORT = 5000         # 监听端口
```

### DNS 服务器配置

默认使用公共 DNS 服务器：

```python
dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
```

## 高级用法

### 自定义 DNS 查询

```python
from dns import DNSQuery
from mc_pinger import MinecraftPinger

# 使用自定义 DNS
dns = DNSQuery(dns_servers=['1.1.1.1', '9.9.9.9'])
pinger = MinecraftPinger("mc.example.com", dns_query=dns)
result = pinger.query()
```

### 批量查询

```python
from mc_pinger import MinecraftPinger

servers = ["mc.hypixel.net", "play.example.com", "127.0.0.1:25565"]

for addr in servers:
    if ":" in addr:
        host, port = addr.split(":")
        port = int(port)
    else:
        host, port = addr, 25565
    
    pinger = MinecraftPinger(host, port)
    result = pinger.query()
    print(f"{host}: {result.get('version_name', 'Offline')}")
```

### 批量 DNS 查询

```python
from dns import DNSQuery

dns = DNSQuery()
results = dns.query_batch(
    ["google.com", "github.com", "minecraft.net"],
    record_type=DNSQuery.TYPE_A
)

for domain, records in results.items():
    for record in records:
        print(f"{domain} -> {record.data}")
```

## 性能优化

- **DNS 缓存**：默认缓存 128 条记录，TTL 300 秒
- **连接复用**：支持复用 `DNSQuery` 实例
- **并发查询**：`query_batch` 使用线程池并发查询
- **Socket 优化**：启用 `TCP_NODELAY` 减少延迟

## 错误处理

| 异常类型 | 说明 |
|----------|------|
| `ConnectionError` | 连接失败（超时、拒绝连接等） |
| `ProtocolError` | 协议解析错误（数据包格式异常） |
| `MinecraftPingerError` | 其他通用错误 |

## 注意事项

1. **协议版本**：默认使用 Minecraft 协议（775），旧版本服务器可能需要调整 `protocol_version`
2. **防火墙**：确保目标服务器端口（默认 25565）可访问
3. **SRV 解析**：仅对域名生效，IP 地址直接连接
4. **HTML页面**：只是一个简单实现，不建议直接部署或暴露外网

## License

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request。
