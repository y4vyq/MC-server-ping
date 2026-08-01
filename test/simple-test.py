import socket
import json
import threading
import struct
import time
import os
import sys
import zlib
import base64
import uuid
import hashlib
from typing import Optional, Dict, Any


class ConfigManager:
    """配置管理器 - 简化配置文件格式"""
    
    def __init__(self, config_file: str = "test.conf"):
        self.config_file = config_file
        self.config_path = os.path.abspath(config_file)
        self._json_cache = None
        self._lock = threading.Lock()
        self._watcher_thread = None
        self._stop_watcher = threading.Event()
        self._last_mtime = 0
        
        # 加载配置
        self.config = self.load_config()
        self.compression_threshold = self.config.get("compression_threshold", -1)
        
        # 启动文件监控
        self.start_file_watcher()
    
    def load_config(self) -> Dict[str, Any]:
        """加载配置文件，如果不存在则创建默认配置"""
        if os.path.exists(self.config_path):
            try:
                config = self.parse_config_file()
                print(f" 已加载配置文件: {self.config_path}")
                return self.normalize_config(config)
            except Exception as e:
                print(f" 加载配置文件失败: {e}，使用默认配置")
                return self.create_default_config()
        else:
            print(f" 配置文件不存在，创建默认配置: {self.config_path}")
            return self.create_default_config()
    
    def parse_config_file(self) -> Dict[str, Any]:
        """解析配置文件"""
        config = {
            "version": "Vanilla 26.1",
            "online": 0,
            "max": 20,
            "players": [],
            "motd": "A Minecraft Server",
            "favicon": ""
        }
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # 跳过空行和注释
                if not line or line.startswith('#'):
                    continue
                
                # 解析键值对
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'version':
                        config['version'] = value
                    elif key == 'online':
                        try:
                            config['online'] = int(value)
                        except ValueError:
                            print(f"  第{line_num}行: online必须是数字，忽略: {value}")
                    elif key == 'max':
                        try:
                            config['max'] = int(value)
                        except ValueError:
                            print(f"  第{line_num}行: max必须是数字，忽略: {value}")
                    elif key == 'motd':
                        config['motd'] = value
                    elif key == 'favicon':
                        config['favicon'] = value
                    elif key == 'players' or key == 'player':
                        player_parts = value.split(',')
                        player = {"name": player_parts[0].strip()}
                        if len(player_parts) > 1 and player_parts[1].strip():
                            player["id"] = player_parts[1].strip()
                        config['players'].append(player)
                    else:
                        print(f"  第{line_num}行: 未知配置项: {key}")
                else:
                    print(f"  第{line_num}行: 格式错误，缺少 '=': {line}")
        
        return config
    
    def normalize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """标准化配置"""
        normalized = {
            "server": {
                "host": "0.0.0.0",
                "port": 25565
            },
            "compression_threshold": -1,
            "login_message": "§cThis is a status query server only.\n§e此服务器仅用于状态查询",
            "version": config.get("version", "Vanilla 26.1"),
            "online": config.get("online", 0),
            "max": config.get("max", 20),
            "sample": [],
            "motd": config.get("motd", "A Minecraft Server"),
            "favicon": config.get("favicon", "")
        }
        
        # 处理玩家列表
        for player in config.get("players", []):
            player_entry = {"name": player.get("name", "Unknown")}
            if "id" in player and player["id"]:
                player_entry["id"] = player["id"]
            else:
                player_entry["id"] = self.generate_uuid()
            normalized["sample"].append(player_entry)
        
        return normalized
    
    def create_default_config(self) -> Dict[str, Any]:
        """创建默认配置文件"""
        default_content = """# Minecraft 服务器状态配置文件
# MOTD 支持多行，使用 \\n 分隔
# 玩家列表格式：name,uuid (uuid可选)

version=Vanilla 26.1
online=1
max=20
players=y4vyq,8667ba71-b85a-4004-af54-457a9734eed7
motd=§a欢迎来到我的世界\\n§e今天天气真好！
favicon=
"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                f.write(default_content)
            print(f" 默认配置已保存到: {self.config_path}")
        except Exception as e:
            print(f" 保存配置文件失败: {e}")
        
        return self.normalize_config(self.parse_config_from_string(default_content))
    
    def parse_config_from_string(self, content: str) -> Dict[str, Any]:
        """从字符串解析配置"""
        config = {
            "version": "Vanilla 26.1",
            "online": 0,
            "max": 20,
            "players": [],
            "motd": "A Minecraft Server",
            "favicon": ""
        }
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'version':
                    config['version'] = value
                elif key == 'online':
                    try:
                        config['online'] = int(value)
                    except:
                        pass
                elif key == 'max':
                    try:
                        config['max'] = int(value)
                    except:
                        pass
                elif key == 'motd':
                    config['motd'] = value
                elif key == 'favicon':
                    config['favicon'] = value
                elif key == 'players' or key == 'player':
                    player_parts = value.split(',')
                    player = {"name": player_parts[0].strip()}
                    if len(player_parts) > 1 and player_parts[1].strip():
                        player["id"] = player_parts[1].strip()
                    config['players'].append(player)
        
        return config
    
    def start_file_watcher(self):
        """启动原生文件监控"""
        if os.path.exists(self.config_path):
            self._last_mtime = os.path.getmtime(self.config_path)
        
        self._watcher_thread = threading.Thread(target=self._watch_file, daemon=True)
        self._watcher_thread.start()
        print(f"  文件监控已启动: {self.config_path}")
    
    def _watch_file(self):
        """监控文件变化"""
        while not self._stop_watcher.is_set():
            try:
                if os.path.exists(self.config_path):
                    current_mtime = os.path.getmtime(self.config_path)
                    
                    if current_mtime != self._last_mtime:
                        self._last_mtime = current_mtime
                        time.sleep(0.5)
                        self._handle_file_change()
                else:
                    print(f"  配置文件不存在，等待重新创建: {self.config_path}")
                    while not self._stop_watcher.is_set():
                        if os.path.exists(self.config_path):
                            self._last_mtime = os.path.getmtime(self.config_path)
                            break
                        time.sleep(1)
                    
            except Exception as e:
                print(f"  文件监控出错: {e}")
            
            time.sleep(1)
    
    def _handle_file_change(self):
        """处理文件变化"""
        print("\n" + "=" * 60)
        print(" 检测到配置文件变化，正在热重载...")
        print("=" * 60)
        
        if self.reload_config():
            print(" 配置热重载成功！")
            self._print_current_config()
            print("=" * 60 + "\n")
        else:
            print("❌ 配置热重载失败，继续使用旧配置")
            print("=" * 60 + "\n")
    
    def _print_current_config(self):
        """打印当前配置摘要"""
        print(f" 当前配置:")
        print(f"   - 版本: {self.config.get('version', 'Unknown')}")
        print(f"   - 在线玩家: {self.config.get('online', 0)}")
        print(f"   - 最大玩家: {self.config.get('max', 20)}")
        motd = self.config.get('motd', 'None')
        motd_display = motd.replace('\\n', ' | ')
        print(f"   - MOTD: {motd_display}")
        players = self.config.get('sample', [])
        print(f"   - 玩家列表 ({len(players)} 个):")
        for i, player in enumerate(players):
            print(f"     [{i}] {player.get('name', 'Unknown')} ({player.get('id', 'No UUID')})")
    
    def stop_file_watcher(self):
        """停止文件监控"""
        self._stop_watcher.set()
        if self._watcher_thread and self._watcher_thread.is_alive():
            self._watcher_thread.join(timeout=2)
        print("👁️  文件监控已停止")
    
    def reload_config(self) -> bool:
        """重新加载配置文件"""
        try:
            with self._lock:
                if not os.path.exists(self.config_path):
                    print(f"  配置文件不存在: {self.config_path}")
                    return False
                
                new_config = self.parse_config_file()
                self.config = self.normalize_config(new_config)
                self.compression_threshold = self.config.get("compression_threshold", -1)
                self._json_cache = None  # 清除缓存
                
                return True
                
        except Exception as e:
            print(f" 重载配置失败: {e}")
            return False
    
    def generate_uuid(self) -> str:
        """生成随机的 Minecraft UUID"""
        return str(uuid.uuid4())
    
    def get_response_data(self) -> Dict[str, Any]:
        """获取 Minecraft 协议格式的响应数据"""
        with self._lock:
            if self._json_cache:
                return self._json_cache.copy()
            
            # 处理玩家列表
            sample_players = []
            for player in self.config.get("sample", []):
                sample_players.append({
                    "name": player.get("name", "Unknown"),
                    "id": player.get("id", self.generate_uuid())
                })
            
            # 处理 MOTD 
            motd_raw = self.config.get("motd", "A Minecraft Server")
            if isinstance(motd_raw, str):
                # 替换 \\n 为实际换行符
                motd_text = motd_raw.replace('\\n', '\n')
                
                # 检查是否包含换行符
                if '\n' in motd_text:
                    lines = motd_text.split('\n')
                    motd = {"text": lines[0] + "\n"}
                    if len(lines) > 1:
                        extra = []
                        for i, line in enumerate(lines[1:]):
                            extra.append({"text": line + ("\n" if i < len(lines) - 2 else "")})
                        motd["extra"] = extra
                else:
                    motd = {"text": motd_text}
            else:
                motd = {"text": str(motd_raw)}
            
            # 处理版本
            version = self.config.get("version", "Vanilla 26.1")
            if isinstance(version, str):
                version = {"name": version, "protocol": 767}
            
            # 构建响应
            response = {
                "version": version,
                "players": {
                    "online": self.config.get("online", 0),
                    "max": self.config.get("max", 20),
                    "sample": sample_players
                },
                "description": motd
            }
            
            # 处理 favicon
            favicon = self.config.get("favicon", "")
            if favicon and favicon.strip():
                if not favicon.startswith("data:image"):
                    favicon_data = self.load_favicon_file(favicon)
                    if favicon_data:
                        response["favicon"] = favicon_data
                else:
                    response["favicon"] = favicon
            
            self._json_cache = response.copy()
            return response
    
    def load_favicon_file(self, favicon_path: str) -> Optional[str]:
        """从文件加载 favicon"""
        try:
            config_dir = os.path.dirname(self.config_path)
            if not os.path.isabs(favicon_path):
                favicon_path = os.path.join(config_dir, favicon_path)
            
            if os.path.exists(favicon_path):
                file_size = os.path.getsize(favicon_path)
                if file_size > 65536:
                    print(f"  Favicon 文件过大 ({file_size} 字节)，跳过加载")
                    return None
                
                with open(favicon_path, 'rb') as f:
                    img_data = f.read()
                    b64_data = base64.b64encode(img_data).decode('utf-8')
                    ext = os.path.splitext(favicon_path)[1].lower()
                    mime_type = {
                        '.png': 'image/png',
                        '.jpg': 'image/jpeg',
                        '.jpeg': 'image/jpeg',
                        '.gif': 'image/gif',
                        '.webp': 'image/webp'
                    }.get(ext, 'image/png')
                    
                    result = f"data:{mime_type};base64,{b64_data}"
                    print(f" 已加载 favicon: {os.path.basename(favicon_path)} ({file_size} 字节)")
                    return result
            else:
                print(f"  Favicon 文件不存在: {favicon_path}")
        except Exception as e:
            print(f"❌ 加载 favicon 失败: {e}")
        
        return None
    
    def get_login_message(self) -> str:
        """获取登录断开消息"""
        return "§cThis is a status query server only.\n§e此服务器仅用于状态查询"
    
    def get_compression_threshold(self) -> int:
        """获取压缩阈值"""
        return -1
    
    def __del__(self):
        """析构函数"""
        self.stop_file_watcher()


def hex_dump(data: bytes, max_len: int = 512) -> str:
    """将字节数据转换为十六进制显示格式"""
    if len(data) > max_len:
        display_data = data[:max_len]
        truncated = f"... (截断，总长度: {len(data)} 字节)"
    else:
        display_data = data
        truncated = ""
    
    result = []
    for i in range(0, len(display_data), 16):
        chunk = display_data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f"{i:04x}: {hex_str:<48} {ascii_str}")
    
    return '\n'.join(result) + ('\n' + truncated if truncated else '')


def write_varint(value: int) -> bytes:
    """写入VarInt（可变长度整数）"""
    result = bytearray()
    while True:
        if value & ~0x7F == 0:
            result.append(value)
            return bytes(result)
        result.append((value & 0x7F) | 0x80)
        value >>= 7


def read_varint(data: bytes, offset: int = 0) -> tuple:
    """读取VarInt，返回(值, 消耗字节数)"""
    result = 0
    shift = 0
    pos = offset
    max_bytes = 5
    
    while True:
        if pos >= len(data):
            raise ValueError("数据不完整")
        if pos - offset >= max_bytes:
            raise ValueError(f"VarInt 超过 {max_bytes} 字节限制")
        
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
    
    return result, pos - offset


def create_response(config: ConfigManager) -> bytes:
    """创建Minecraft服务器状态响应数据包"""
    response_data = config.get_response_data()
    json_str = json.dumps(response_data, ensure_ascii=False)
    json_bytes = json_str.encode('utf-8')
    
    packet_id = write_varint(0x00)
    json_length = write_varint(len(json_bytes))
    
    packet = packet_id + json_length + json_bytes
    return packet


def create_packet_with_compression(payload: bytes, config: ConfigManager) -> bytes:
    """创建带压缩的数据包"""
    threshold = config.get_compression_threshold()
    
    if threshold < 0 or len(payload) < threshold:
        packet_len = write_varint(len(payload))
        return packet_len + payload
    
    compressed_data = zlib.compress(payload)
    data_len = write_varint(len(payload))
    full_packet = data_len + compressed_data
    packet_len = write_varint(len(full_packet))
    
    print(f"📦 数据包已压缩: {len(payload)} -> {len(compressed_data)} 字节")
    return packet_len + full_packet


def create_login_disconnect_response(config: ConfigManager) -> bytes:
    """创建登录断开连接响应包"""
    reason = config.get_login_message()
    json_reason = json.dumps({"text": reason}, ensure_ascii=False)
    json_bytes = json_reason.encode('utf-8')
    
    packet_id = write_varint(0x00)
    json_length = write_varint(len(json_bytes))
    
    packet = packet_id + json_length + json_bytes
    return packet


def handle_legacy_ping(data: bytes, client_socket: socket.socket, config: ConfigManager) -> bool:
    """处理旧版Minecraft ping协议"""
    if len(data) < 2 or data[0] != 0xFE or data[1] != 0x01:
        return False
    
    response_data = config.get_response_data()
    motd = response_data.get("description", {}).get("text", "Minecraft Server")
    online = str(response_data.get("players", {}).get("online", 0))
    max_players = str(response_data.get("players", {}).get("max", 20))
    
    response_str = f"\x00{motd}\x00{online}\x00{max_players}"
    utf16_bytes = response_str.encode('utf-16be')
    response = b'\xff' + struct.pack('>H', len(utf16_bytes)) + utf16_bytes
    
    client_socket.send(response)
    return True


def handle_login_handshake(packet_data: bytes, client_socket: socket.socket, id_bytes: int, config: ConfigManager) -> bool:
    """处理登录握手包"""
    current_pos = id_bytes
    
    try:
        protocol_version, varint_bytes = read_varint(packet_data, current_pos)
        current_pos += varint_bytes
    except ValueError:
        return False
    
    try:
        addr_len, varint_bytes = read_varint(packet_data, current_pos)
        current_pos += varint_bytes
        if current_pos + addr_len <= len(packet_data):
            current_pos += addr_len
        else:
            return False
    except (ValueError, UnicodeDecodeError):
        return False
    
    if current_pos + 2 <= len(packet_data):
        current_pos += 2
    else:
        return False
    
    try:
        next_state, varint_bytes = read_varint(packet_data, current_pos)
    except ValueError:
        return False
    
    response = create_login_disconnect_response(config)
    full_response = create_packet_with_compression(response, config)
    client_socket.send(full_response)
    return True


def handle_handshake_packet(packet_data: bytes, client_socket: socket.socket, id_bytes: int, config: ConfigManager) -> bool:
    """处理握手包"""
    current_pos = id_bytes
    
    try:
        protocol_version, varint_bytes = read_varint(packet_data, current_pos)
        current_pos += varint_bytes
    except ValueError:
        return False
    
    try:
        addr_len, varint_bytes = read_varint(packet_data, current_pos)
        current_pos += varint_bytes
        if current_pos + addr_len <= len(packet_data):
            current_pos += addr_len
        else:
            return False
    except (ValueError, UnicodeDecodeError):
        return False
    
    if current_pos + 2 <= len(packet_data):
        current_pos += 2
    else:
        return False
    
    try:
        next_state, varint_bytes = read_varint(packet_data, current_pos)
        
        if next_state == 1:
            return True
        elif next_state == 2:
            return handle_login_handshake(packet_data, client_socket, id_bytes, config)
            
    except ValueError:
        return False
    
    return False


def handle_new_protocol(data: bytes, client_socket: socket.socket, config: ConfigManager) -> bool:
    """处理新版Minecraft协议"""
    try:
        pos = 0
        
        while pos < len(data):
            try:
                packet_len, varint_bytes = read_varint(data, pos)
                
                if packet_len > 2097152:
                    return False
                
                pos += varint_bytes
                
                if pos + packet_len > len(data):
                    break
                
                packet_data = data[pos:pos + packet_len]
                pos += packet_len
                
                if len(packet_data) > 0:
                    packet_id, id_bytes = read_varint(packet_data, 0)
                    
                    if packet_id == 0x00:
                        if len(packet_data) <= id_bytes + 1:
                            response = create_response(config)
                            full_response = create_packet_with_compression(response, config)
                            client_socket.send(full_response)
                        else:
                            handle_handshake_packet(packet_data, client_socket, id_bytes, config)
                            
                    elif packet_id == 0x01:
                        if len(packet_data) >= id_bytes + 8:
                            ping_payload = struct.unpack('>Q', packet_data[id_bytes:id_bytes + 8])[0]
                            pong_packet = write_varint(0x01) + struct.pack('>Q', ping_payload)
                            pong_len = write_varint(len(pong_packet))
                            full_pong = pong_len + pong_packet
                            client_socket.send(full_pong)
                            return False
                        
            except Exception as e:
                break
        
        return True
        
    except Exception:
        return False


def handle_client(client_socket: socket.socket, client_address: tuple, config: ConfigManager) -> None:
    """处理客户端连接"""
    try:
        client_socket.settimeout(10)
        
        initial_data = bytearray()
        while True:
            try:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                initial_data.extend(chunk)
                
                if len(initial_data) >= 3:
                    if initial_data[0] == 0xFE:
                        break
                    elif initial_data[0] & 0x7F:
                        try:
                            packet_len, _ = read_varint(bytes(initial_data), 0)
                            if len(initial_data) >= packet_len + len(write_varint(packet_len)):
                                break
                        except:
                            pass
                        
            except socket.timeout:
                break
        
        if not initial_data:
            return
        
        data = bytes(initial_data)
        
        client_ip = client_address[0]
        
        if len(data) >= 2 and data[0] == 0xFE and data[1] == 0x01:
            handle_legacy_ping(data, client_socket, config)
            return
        
        keep_alive = handle_new_protocol(data, client_socket, config)
        
        if keep_alive:
            client_socket.settimeout(5)
            
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    
                    keep_alive = handle_new_protocol(chunk, client_socket, config)
                    if not keep_alive:
                        break
                        
                except socket.timeout:
                    break
                except Exception:
                    break
        
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass


class DualStackServer:
    """双栈服务器"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.sockets = []
        self.running = True
    
    def start(self):
        """启动双栈服务器"""
        host = self.config.config.get("server", {}).get("host", "0.0.0.0")
        port = self.config.config.get("server", {}).get("port", 25565)
        
        ipv6_enabled = False
        try:
            ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            ipv6_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                ipv6_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                ipv6_enabled = True
                print(" IPv6 双栈模式已启用")
            except:
                pass
            
            ipv6_socket.bind(('::', port))
            ipv6_socket.listen(5)
            self.sockets.append(('IPv6', ipv6_socket))
            print(f" IPv6 监听 [::]:{port}")
        except Exception as e:
            print(f"  无法创建 IPv6 socket: {e}")
        
        if not ipv6_enabled:
            try:
                ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ipv4_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                ipv4_socket.bind((host, port))
                ipv4_socket.listen(5)
                self.sockets.append(('IPv4', ipv4_socket))
                print(f" IPv4 监听 {host}:{port}")
            except Exception as e:
                print(f" 无法创建 IPv4 socket: {e}")
        
        if not self.sockets:
            print(" 无法启动任何 socket")
            return
        
        print(f"\n 修改 {self.config.config_file} 文件可实时调整配置")
        print("按 Ctrl+C 停止服务器")
        print("=" * 60)
        
        try:
            while self.running:
                try:
                    import select
                    read_sockets = [s[1] for s in self.sockets]
                    ready_sockets, _, _ = select.select(read_sockets, [], [], 1.0)
                    
                    for sock in ready_sockets:
                        try:
                            client_socket, client_address = sock.accept()
                            proto_name = next((s[0] for s in self.sockets if s[1] == sock), 'Unknown')
                            
                            client_thread = threading.Thread(
                                target=handle_client,
                                args=(client_socket, client_address, self.config)
                            )
                            client_thread.daemon = True
                            client_thread.start()
                        except Exception:
                            pass
                            
                except KeyboardInterrupt:
                    raise
                except Exception:
                    pass
                        
        except KeyboardInterrupt:
            print("\n 服务器正在停止...")
        finally:
            self.stop()
    
    def stop(self):
        """停止服务器"""
        self.running = False
        for sock_info in self.sockets:
            try:
                sock_info[1].close()
            except:
                pass


def start_server(config: ConfigManager) -> None:
    """启动服务器"""
    server = DualStackServer(config)
    server.start()


def print_usage():
    """打印使用说明"""
    print("""
Minecraft 服务器状态模拟器
使用方法:
    python server.py              # 使用默认配置文件 test.conf
    python server.py config.conf  # 使用指定的配置文件

配置文件格式 (test.conf):
    version=Vanilla 26.1
    online=1
    max=20
    players=PlayerName,UUID
    motd=第一行\\n第二行
    favicon=server-icon.png
""")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print_usage()
            sys.exit(0)
        config_file = sys.argv[1]
    else:
        config_file = "test.conf"
    
    print(f" 使用配置文件: {config_file}")
    config = ConfigManager(config_file)
    
    try:
        start_server(config)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n 清理资源...")
        config.stop_file_watcher()
        print(" 服务器已停止")
