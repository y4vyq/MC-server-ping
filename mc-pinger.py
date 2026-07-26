import socket
import json
import struct
from io import BytesIO
from typing import Optional, Dict, Any, List, Union
import time
import random
from contextlib import contextmanager
import logging
import ipaddress

from dns import DNSQuery

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
    自动 SRV 记录解析（支持加权随机选择），支持 IPv4 和 IPv6 连接
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
        self.original_host = host
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
        self._srv_targets = []  # 存储解析出的 SRV 目标列表

    @staticmethod
    def _weighted_random_choice(srv_records):

        if not srv_records:
            return None
        
        # 按优先级分组
        priority_groups = {}
        for record in srv_records:
            priority = record.data.priority
            priority_groups.setdefault(priority, []).append(record)
        
        # 选择最高优先级（数字最小）
        best_priority = min(priority_groups.keys())
        candidates = priority_groups[best_priority]
        
        # 同优先级内加权随机选择
        total_weight = sum(r.data.weight for r in candidates)
        if total_weight == 0:
            return random.choice(candidates)
        
        rand = random.randint(0, total_weight - 1)
        cumulative = 0
        for r in candidates:
            cumulative += r.data.weight
            if rand < cumulative:
                return r
        return candidates[-1]

    def _resolve_srv(self):

        if self._srv_resolved:
            return

        if self.enable_srv:
            srv_domain = f'_minecraft._tcp.{self.original_host}'
            try:
                records = self.dns.query(srv_domain, DNSQuery.TYPE_SRV, use_cache=True)
                if records:
                    # 筛选出 SRV 记录
                    srv_records = [r for r in records if r.type == DNSQuery.TYPE_SRV]
                    if srv_records:
                        # RFC 2782 加权随机选择
                        chosen = self._weighted_random_choice(srv_records)
                        if chosen:
                            new_host = chosen.data.target.rstrip('.')  # 移除可能的末尾点
                            new_port = chosen.data.port
                            logger.info(
                                f"SRV 解析成功: {self.original_host} -> {new_host}:{new_port} "
                                f"(优先级:{chosen.data.priority}, 权重:{chosen.data.weight})"
                            )
                            self.host = new_host
                            self.port = new_port
                            
                            # 存储所有可用目标（用于故障转移）
                            self._srv_targets = [
                                (r.data.target.rstrip('.'), r.data.port, r.data.priority)
                                for r in srv_records
                            ]
            except Exception as e:
                logger.warning(
                    f"SRV 解析失败，将使用默认地址 {self.original_host}:{self.port}，原因: {e}"
                )

        self._srv_resolved = True

    @contextmanager
    def _create_socket(self, connect_timeout: Optional[float] = None):
        """创建并管理 socket 连接，自动支持 IPv4/IPv6"""
        sock = None
        timeout = connect_timeout if connect_timeout is not None else self.timeout
        try:
            # create_connection 会调用 getaddrinfo 并依次尝试所有地址（包括 IPv6）
            sock = socket.create_connection((self.host, self.port), timeout=timeout)
            sock.settimeout(self.timeout)  # 后续 recv 超时
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # 设置 SO_KEEPALIVE 防止长时间空闲断开
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            yield sock
        except OSError as e:
            # 将所有底层 socket 错误统一为自定义 ConnectionError
            raise ConnectionError(f"连接失败 {self.host}:{self.port} - {e}") from e
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                finally:
                    sock.close()

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
        try:
            sock.sendall(full_packet)
        except OSError as e:
            raise ConnectionError(f"发送数据包失败: {e}")

    def _read_packet(self, sock: socket.socket) -> bytes:
        """读取完整的 Minecraft 数据包"""
        length = self._read_varint_from_socket(sock)
        if length <= 0:
            raise ProtocolError(f"Invalid packet length: {length}")
        if length > self.MAX_JSON_SIZE + 10:
            raise ProtocolError(f"Packet too large: {length} bytes")

        data = bytearray()
        bytes_read = 0
        while bytes_read < length:
            try:
                chunk = sock.recv(min(length - bytes_read, 4096))
                if not chunk:
                    raise ConnectionError("Connection closed while reading packet")
                data.extend(chunk)
                bytes_read += len(chunk)
            except socket.timeout:
                raise ConnectionError(f"读取数据包超时 (已读取 {bytes_read}/{length} bytes)")
            except OSError as e:
                raise ConnectionError(f"读取数据包失败: {e}")
        return bytes(data)

    def _read_varint_from_socket(self, sock: socket.socket) -> int:
        """从 socket 直接读取 VarInt"""
        value = 0
        shift = 0
        while True:
            try:
                byte_data = sock.recv(1)
            except socket.timeout:
                raise ConnectionError("读取 VarInt 超时")
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
        """
        执行 Ping/Pong 并返回延迟（毫秒）
        使用高性能计时器避免系统时间调整影响
        """
        ping_start = time.perf_counter()
        ping_payload = struct.pack('>Q', int(ping_start * 1000))
        self._write_packet(sock, 0x01, ping_payload)

        response = self._read_packet(sock)
        stream = BytesIO(response)
        packet_id = self.decode_varint(stream)
        if packet_id != 0x01:
            raise ProtocolError(f"Expected Pong packet (ID 0x01), got {packet_id}")

        pong_payload = stream.read(8)
        if len(pong_payload) != 8:
            raise ProtocolError("Incomplete Pong payload")
        
        # 使用 perf_counter 计算真实往返时间，不受系统时间调整影响
        ping_end = time.perf_counter()
        ping_ms = int((ping_end - ping_start) * 1000)
        return max(ping_ms, 0)

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
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
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
            "favicon": None,
            "mod_info": None  # Forge/Fabric 模组信息
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
                    {"name": p.get("name", "Unknown"), "id": p.get("id", "")}
                    for p in sample if isinstance(p, dict)
                ]

        if "description" in data:
            desc = data["description"]
            result["description_raw"] = desc
            result["description"] = self._parse_chat_component(desc)

        if "favicon" in data:
            result["favicon"] = data["favicon"]

        # 模组信息（Forge/Fabric 等）
        if "modinfo" in data:
            result["mod_info"] = data["modinfo"]
        if "forgeData" in data:
            result["mod_info"] = data["forgeData"]

        return result

    def _parse_chat_component(self, component: Union[str, Dict[str, Any]], 
                              default_color: str = "") -> str:
        """
        递归解析 Minecraft 聊天组件为纯文本
        
        支持更多格式：
        - text, translate, with
        - extra, color, bold, italic 等样式（忽略，仅提取文本）
        - keybind, score, selector 等特殊组件
        """
        if isinstance(component, str):
            return component
        if not isinstance(component, dict):
            return str(component)

        parts = []

        # 提取直接文本内容
        if "text" in component:
            parts.append(component["text"])

        # 翻译文本
        if "translate" in component:
            key = component["translate"]
            with_args = component.get("with", [])
            if with_args:
                try:
                    args = [self._parse_chat_component(arg) for arg in with_args]
                    # 简单的占位符替换
                    text = key
                    for arg in args:
                        if "%s" in text:
                            text = text.replace("%s", arg, 1)
                        elif "%%s" in text:
                            text = text.replace("%%s", "%s", 1)
                        else:
                            text += arg
                    parts.append(text)
                except Exception:
                    parts.append(key)
            else:
                parts.append(key)

        # 快捷键绑定
        if "keybind" in component:
            parts.append(f"[{component['keybind']}]")

        # 计分板值
        if "score" in component:
            score = component["score"]
            name = score.get("name", "?")
            objective = score.get("objective", "?")
            parts.append(f"[{name}:{objective}]")

        # 实体选择器
        if "selector" in component:
            parts.append(f"[{component['selector']}]")

        # 递归处理子元素
        if "extra" in component:
            for child in component["extra"]:
                parts.append(self._parse_chat_component(child))

        # 处理换行符（某些服务器用 \n 分隔多行 MOTD）
        text = "".join(parts)
        
        # 清理格式代码（§ 符号 + 颜色/格式代码）
        import re
        text = re.sub(r'§[0-9a-fk-or]', '', text, flags=re.IGNORECASE)
        
        return text

    def _query_once(self) -> Dict[str, Any]:
        """执行单次查询（不包含重试逻辑）"""
        with self._create_socket() as sock:
            # 握手
            self._send_handshake(sock)
            
            # 请求状态
            self._write_packet(sock, 0x00, b'')  # Status Request
            
            # 读取响应
            response_data = self._read_packet(sock)
            response = self._parse_status_response(response_data)

            # 测量延迟
            ping_ms = None
            if self.enable_ping:
                try:
                    ping_ms = self._do_ping(sock)
                except Exception as e:
                    logger.debug(f"Ping 测量失败: {e}")

            result = self._build_result(response)
            if ping_ms is not None:
                result["ping"] = ping_ms
            return result

    def query(self) -> Dict[str, Any]:
        """
        执行服务器查询（自动 SRV + IPv4/IPv6 双栈）
        
        Returns:
            包含服务器信息的字典，成功时 "success" 为 True
        """
        # 在重试前完成一次 SRV 解析
        if not self._srv_resolved:
            self._resolve_srv()

        last_error = None
        for attempt in range(self.retries + 1):
            try:
                result = self._query_once()
                # 添加解析信息
                result["resolved_host"] = self.host
                result["resolved_port"] = self.port
                result["original_host"] = self.original_host
                return result
            except ConnectionError as e:
                last_error = str(e)
                logger.debug(f"连接尝试 {attempt + 1}/{self.retries + 1} 失败: {e}")
                if attempt < self.retries:
                    time.sleep(self.retry_delay)
                    continue
                else:
                    return {
                        "success": False,
                        "error": f"连接失败: {last_error}",
                        "host": self.host,
                        "port": self.port
                    }
            except ProtocolError as e:
                return {
                    "success": False,
                    "error": f"协议错误: {e}",
                    "host": self.host,
                    "port": self.port
                }
            except Exception as e:
                logger.error(f"未预期的错误: {e}", exc_info=True)
                return {
                    "success": False,
                    "error": f"未预期的错误: {e}",
                    "host": self.host,
                    "port": self.port
                }

        return {
            "success": False,
            "error": f"所有重试均失败: {last_error}",
            "host": self.host,
            "port": self.port
        }

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
        motd = result.get("description", "")

        parts = [f" {version}", f" {online}/{max_players}"]
        if ping is not None and ping >= 0:
            parts.append(f" {ping}ms")
        if motd:
            # 截取第一行 MOTD
            motd_first_line = motd.split('\n')[0][:50]
            parts.append(f" {motd_first_line}")
        return " | ".join(parts)
