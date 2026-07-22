import socket
import json
import struct
from io import BytesIO
from typing import Optional, Dict, Any, List, Union, Tuple
import time
from contextlib import contextmanager
import logging

# 导入自制的 DNS 查询模块
from dns import DNSQuery, MinecraftServerResolver

logger = logging.getLogger(__name__)


class MinecraftPingerError(Exception):
    """Minecraft Pinger 基础异常类"""
    pass


class ConnectionError(MinecraftPingerError):
    """连接相关异常"""
    pass


class ProtocolError(MinecraftPingerError):
    """协议解析相关异常"""
    pass


class MinecraftPinger:
    """
    Minecraft Java 版服务器列表 Ping 工具
    支持自动 SRV 记录解析（无需手动处理）
    """

    # Minecraft 协议常量
    STATE_HANDSHAKE = 0
    STATE_STATUS = 1
    STATE_LOGIN = 2

    # 最大 JSON 响应大小（防止恶意服务器）
    MAX_JSON_SIZE = 1024 * 1024  # 1MB

    def __init__(
        self,
        host: str,
        port: int = 25565,
        protocol_version: int = 775,
        timeout: float = 5.0,
        retries: int = 2,
        retry_delay: float = 1.0,
        enable_ping: bool = True,
        dns_query: Optional[DNSQuery] = None,
        enable_srv: bool = True
    ):
        """
        初始化 Minecraft Pinger

        Args:
            host: 服务器地址（IP 或域名）
            port: 服务器端口，默认 25565
            protocol_version: 协议版本号，默认 775 (1.21)
            timeout: 连接和读取超时时间（秒）
            retries: 失败重试次数（不包括首次尝试）
            retry_delay: 重试间隔（秒）
            enable_ping: 是否执行 Ping 测量延迟
            dns_query: 可复用的 DNSQuery 实例，为 None 时自动创建
            enable_srv: 是否启用 SRV 记录解析（默认 True）
        """
        self.original_host = host  # 保留原始主机名，供日志使用
        self.host = host
        self.port = port
        self.protocol_version = protocol_version
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.enable_ping = enable_ping

        # DNS 解析相关
        self.dns = dns_query if dns_query is not None else DNSQuery()
        self.enable_srv = enable_srv
        self._srv_resolved = False

        # 旧的 DNS 缓存（可选，可继续保留用于 A 记录缓存）
        self._dns_cache: Optional[str] = None
        self._dns_cache_time = 0
        self._dns_cache_ttl = 60

    def _resolve_srv(self):
        """
        通过 SRV 记录解析真实的目标主机和端口。
        仅在首次调用时执行（且 enable_srv=True），结果会直接修改 self.host / self.port。
        """
        if self._srv_resolved:
            return

        if self.enable_srv:
            srv_domain = f'_minecraft._tcp.{self.original_host}'
            try:
                records = self.dns.query(srv_domain, DNSQuery.TYPE_SRV, use_cache=True)
                if records:
                    # 按优先级排序，相同优先级则权重高的优先（简化实现）
                    sorted_records = sorted(records,
                                            key=lambda r: (r.data.priority, -r.data.weight))
                    best = sorted_records[0]
                    new_host = best.data.target
                    new_port = best.data.port
                    logger.info(f"SRV 解析成功: {self.original_host} -> {new_host}:{new_port}")
                    self.host = new_host
                    self.port = new_port
            except Exception as e:
                logger.warning(f"SRV 解析失败，将使用默认地址 {self.original_host}:{self.port}，原因: {e}")

        self._srv_resolved = True

    @contextmanager
    def _create_socket(self):
        """创建并管理 socket 连接"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            ip = self._resolve_host()
            sock.connect((ip, self.port))
            yield sock
        finally:
            sock.close()

    def _resolve_host(self) -> str:
        """解析主机名（A/AAAA），带本地 DNS 缓存"""
        # 如果已经是 IP 地址，直接返回
        try:
            socket.inet_aton(self.host)
            return self.host
        except socket.error:
            pass

        now = time.time()
        if (self._dns_cache and
                now - self._dns_cache_time < self._dns_cache_ttl):
            return self._dns_cache

        self._dns_cache = None  # 过期清除
        try:
            ip = socket.gethostbyname(self.host)
            self._dns_cache = ip
            self._dns_cache_time = now
            return ip
        except socket.gaierror as e:
            raise ConnectionError(f"Failed to resolve host '{self.host}': {e}")

    @staticmethod
    def encode_varint(value: int) -> bytes:
        """将整数编码为 VarInt"""
        if value < 0:
            raise ValueError("VarInt cannot be negative")
        buf = []
        while True:
            temp = value & 0x7F
            value >>= 7
            if value != 0:
                temp |= 0x80
            buf.append(temp)
            if value == 0:
                break
        return bytes(buf)

    @staticmethod
    def decode_varint(stream: BytesIO) -> int:
        """从字节流解码 VarInt"""
        value = 0
        shift = 0
        while True:
            byte_data = stream.read(1)
            if not byte_data:
                raise ProtocolError("Unexpected end of VarInt stream")
            b = byte_data[0]
            value |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift >= 32:
                raise ProtocolError("VarInt too large")
        return value

    def _write_packet(self, sock: socket.socket, packet_id: int, data: bytes):
        """发送完整的 Minecraft 数据包"""
        packet_data = self.encode_varint(packet_id) + data
        full_packet = self.encode_varint(len(packet_data)) + packet_data
        sock.sendall(full_packet)

    def _read_packet(self, sock: socket.socket) -> bytes:
        """读取完整的 Minecraft 数据包"""
        length = self._read_varint_from_socket(sock)
        if length <= 0:
            raise ProtocolError(f"Invalid packet length: {length}")
        if length > self.MAX_JSON_SIZE + 10:
            raise ProtocolError(f"Packet too large: {length} bytes")

        data = bytearray()
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed while reading packet")
            data.extend(chunk)
        return bytes(data)

    def _read_varint_from_socket(self, sock: socket.socket) -> int:
        """从 socket 直接读取 VarInt"""
        value = 0
        shift = 0
        while True:
            byte_data = sock.recv(1)
            if not byte_data:
                raise ConnectionError("Connection closed while reading VarInt")
            b = byte_data[0]
            value |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift >= 32:
                raise ProtocolError("VarInt too large")
        return value

    def _send_handshake(self, sock: socket.socket):
        """发送握手包"""
        host_bytes = self.host.encode('utf-8')
        handshake_data = (
            self.encode_varint(self.protocol_version) +
            self.encode_varint(len(host_bytes)) +
            host_bytes +
            struct.pack('>H', self.port) +
            self.encode_varint(self.STATE_STATUS)
        )
        self._write_packet(sock, 0x00, handshake_data)

    def _do_ping(self, sock: socket.socket) -> int:
        """执行 Ping/Pong 并返回延迟（毫秒）"""
        timestamp = int(time.time() * 1000)
        ping_data = struct.pack('>Q', timestamp)
        self._write_packet(sock, 0x01, ping_data)

        response = self._read_packet(sock)
        stream = BytesIO(response)
        packet_id = self.decode_varint(stream)
        if packet_id != 0x01:
            raise ProtocolError(f"Expected Pong packet (ID 0x01), got {packet_id}")

        pong_timestamp_bytes = stream.read(8)
        if len(pong_timestamp_bytes) != 8:
            raise ProtocolError("Incomplete Pong timestamp")
        pong_timestamp = struct.unpack('>Q', pong_timestamp_bytes)[0]

        current_time = int(time.time() * 1000)
        ping_ms = current_time - pong_timestamp
        return max(ping_ms, 0)  # 防止负数

    def _parse_status_response(self, data: bytes) -> Dict[str, Any]:
        """解析 Status Response 包，返回 JSON 数据"""
        stream = BytesIO(data)
        packet_id = self.decode_varint(stream)
        if packet_id != 0x00:
            raise ProtocolError(f"Expected Status Response (ID 0x00), got {packet_id}")

        json_length = self.decode_varint(stream)
        if json_length > self.MAX_JSON_SIZE:
            raise ProtocolError(f"JSON response too large: {json_length} bytes")

        json_bytes = stream.read(json_length)
        if len(json_bytes) != json_length:
            raise ProtocolError("Incomplete JSON data")
        try:
            return json.loads(json_bytes.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ProtocolError(f"Invalid JSON response: {e}")

    def _build_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """从原始 JSON 构建标准化结果"""
        result = {
            "success": True,
            "version_name": "Unknown",
            "protocol": 0,
            "online_players": 0,
            "max_players": 0,
            "player_sample": [],
            "description": "",
            "description_raw": None,
            "favicon": None
        }

        if "version" in data:
            result["version_name"] = data["version"].get("name", "Unknown")
            result["protocol"] = data["version"].get("protocol", 0)

        if "players" in data:
            players = data["players"]
            result["online_players"] = players.get("online", 0)
            result["max_players"] = players.get("max", 0)
            sample = players.get("sample", [])
            if sample:
                result["player_sample"] = [
                    p.get("name", "Unknown") for p in sample if isinstance(p, dict)
                ]

        if "description" in data:
            desc = data["description"]
            result["description_raw"] = desc
            result["description"] = self._parse_chat_component(desc)

        if "favicon" in data:
            result["favicon"] = data["favicon"]

        return result

    def _parse_chat_component(self, component: Union[str, Dict[str, Any]]) -> str:
        """递归解析 Minecraft 聊天组件为纯文本"""
        if isinstance(component, str):
            return component
        if not isinstance(component, dict):
            return str(component)

        parts = []

        if "text" in component:
            parts.append(component["text"])

        if "translate" in component:
            key = component["translate"]
            with_args = component.get("with", [])
            if with_args:
                try:
                    args = [self._parse_chat_component(arg) for arg in with_args]
                    text = key
                    for arg in args:
                        text = text.replace("%s", arg, 1)
                    parts.append(text)
                except Exception:
                    parts.append(key)
            else:
                parts.append(key)

        if "extra" in component:
            for child in component["extra"]:
                parts.append(self._parse_chat_component(child))

        return "".join(parts)

    def _query_once(self) -> Dict[str, Any]:
        """执行单次查询（不包含重试逻辑）"""
        with self._create_socket() as sock:
            self._send_handshake(sock)
            self._write_packet(sock, 0x00, b'')  # Status Request
            response_data = self._read_packet(sock)
            response = self._parse_status_response(response_data)

            ping_ms = None
            if self.enable_ping:
                ping_ms = self._do_ping(sock)

            result = self._build_result(response)
            if ping_ms is not None:
                result["ping"] = ping_ms
            return result

    def query(self) -> Dict[str, Any]:
        """
        执行服务器查询（自动处理 SRV 解析）
        """
        # 在重试前完成一次 SRV 解析
        if not self._srv_resolved:
            self._resolve_srv()

        last_error = None
        for attempt in range(self.retries + 1):
            try:
                return self._query_once()
            except (ConnectionError, socket.timeout) as e:
                last_error = str(e)
                if attempt < self.retries:
                    time.sleep(self.retry_delay)
                    continue
                else:
                    return {"success": False, "error": f"Connection failed: {last_error}"}
            except ProtocolError as e:
                return {"success": False, "error": f"Protocol error: {e}"}
            except Exception as e:
                return {"success": False, "error": f"Unexpected error: {e}"}

        return {"success": False, "error": f"All retries failed: {last_error}"}

    def query_simple(self) -> Optional[Dict[str, Any]]:
        """简化查询，失败返回 None"""
        result = self.query()
        return result if result.get("success") else None

    def get_status_string(self) -> str:
        """获取格式化的状态字符串"""
        result = self.query()
        if not result.get("success"):
            return f" {result.get('error', 'Unknown error')}"

        version = result.get("version_name", "Unknown")
        online = result.get("online_players", 0)
        max_players = result.get("max_players", 0)
        ping = result.get("ping", -1)

        parts = [f"版本: {version}", f"玩家: {online}/{max_players}"]
        if ping >= 0:
            parts.append(f"延迟: {ping}ms")
        return " | ".join(parts)


# ------------------- 简单使用示例 -------------------
if __name__ == "__main__":
    # 使用自定义 DNS 服务器（可选）
    custom_dns = DNSQuery(dns_servers=['1.1.1.1', '8.8.8.8'])
    pinger = MinecraftPinger("mc.hypixel.net", dns_query=custom_dns)

    print("正在查询服务器...")
    result = pinger.query()
    if result["success"]:
        print(" 服务器在线")
        print(f"  版本: {result['version_name']} (协议 {result['protocol']})")
        print(f"  玩家: {result['online_players']}/{result['max_players']}")
        print(f"  描述: {result['description']}")
        if result.get("ping"):
            print(f"  延迟: {result['ping']} ms")
        if result.get("player_sample"):
            print(f"  在线玩家: {', '.join(result['player_sample'][:10])}")
    else:
        print(f" 查询失败: {result['error']}")
