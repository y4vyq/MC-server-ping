import socket
import json
import threading
import struct
import time
import os
import sys
import zlib
import base64
from typing import Optional, Dict, Any

# 默认配置（仅在配置文件不存在时使用）
DEFAULT_CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 25565,
        "compression_threshold": -1  # 默认禁用压缩，避免兼容性问题
    },
    "response": {
        "version": {
            "name": "Requires MC 1.8 / 1.21",
            "protocol": 775
        },
        "players": {
            "online": 29983,
            "max": 200000,
            "sample": []
        },
        "description": {
            "text": "§f                 §aHypixel Network §c[1.8/26.2]\n§f       §3§lSB 0.26 §b§lLOADOUTS & RESOURCE PACK"
        },
        "favicon": None
    },
    "login_message": "§cThis is a status query server only.\n§e此服务器仅用于状态查询"
}


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_file: str = "test.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.compression_threshold = self.config.get("server", {}).get("compression_threshold", -1)
        
    def load_config(self) -> Dict[str, Any]:
        """加载配置文件，如果不存在则创建默认配置"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                print(f" 已加载配置文件: {self.config_file}")
                return config
            except Exception as e:
                print(f" 加载配置文件失败: {e}，使用默认配置")
                return self.create_default_config()
        else:
            print(f" 配置文件不存在，创建默认配置: {self.config_file}")
            return self.create_default_config()
    
    def create_default_config(self) -> Dict[str, Any]:
        """创建默认配置文件"""
        config = DEFAULT_CONFIG.copy()
        self.save_config(config)
        return config
    
    def save_config(self, config: Dict[str, Any]) -> None:
        """保存配置文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            print(f" 配置已保存到: {self.config_file}")
        except Exception as e:
            print(f"❌ 保存配置文件失败: {e}")
    
    def get_response_data(self) -> Dict[str, Any]:
        """获取响应数据（支持两种JSON格式）"""
        if "response" in self.config:
            response = self.config.get("response", {}).copy()
        else:
            response = self.config.copy()
            for key in ["server", "login_message", "compression_threshold"]:
                response.pop(key, None)
        
        if not response or "version" not in response:
            print(" 配置中缺少 response 数据，使用默认配置")
            response = DEFAULT_CONFIG["response"].copy()
        
        # 处理favicon
        favicon = response.get("favicon")
        if favicon and isinstance(favicon, str) and favicon.strip():
            if not favicon.startswith("data:image"):
                try:
                    config_dir = os.path.dirname(self.config_file)
                    if config_dir and not os.path.isabs(favicon):
                        favicon_path = os.path.join(config_dir, favicon)
                    else:
                        favicon_path = favicon
                    
                    if os.path.exists(favicon_path):
                        with open(favicon_path, 'rb') as f:
                            img_data = f.read()
                            b64_data = base64.b64encode(img_data).decode('utf-8')
                            ext = os.path.splitext(favicon_path)[1].lower()
                            mime_type = {
                                '.png': 'image/png',
                                '.jpg': 'image/jpeg',
                                '.jpeg': 'image/jpeg',
                                '.gif': 'image/gif',
                                '.webp': 'image/webp',
                                '.bmp': 'image/bmp',
                                '.ico': 'image/x-icon'
                            }.get(ext, 'image/png')
                            response["favicon"] = f"data:{mime_type};base64,{b64_data}"
                            print(f" 已加载favicon: {favicon_path}")
                    else:
                        print(f" Favicon文件不存在: {favicon_path}")
                        response.pop("favicon", None)
                except Exception as e:
                    print(f" 加载favicon失败: {e}")
                    response.pop("favicon", None)
        elif favicon is None or favicon == "":
            response.pop("favicon", None)
        
        return response
    
    def get_login_message(self) -> str:
        """获取登录断开消息"""
        return self.config.get("login_message", DEFAULT_CONFIG["login_message"])
    
    def get_compression_threshold(self) -> int:
        """获取压缩阈值"""
        return self.compression_threshold


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
    while True:
        if pos >= len(data):
            raise ValueError("数据不完整")
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
    """
    创建带压缩的数据包
    格式: [包长度(VarInt)] [数据长度(VarInt)] [压缩数据]
    """
    threshold = config.get_compression_threshold()
    
    # 如果阈值 < 0 或者数据包小于阈值，不压缩
    if threshold < 0 or len(payload) < threshold:
        packet_len = write_varint(len(payload))
        return packet_len + payload
    
    # 压缩数据
    compressed_data = zlib.compress(payload)
    
    # 数据长度是压缩前的原始长度
    data_len = write_varint(len(payload))
    full_packet = data_len + compressed_data
    packet_len = write_varint(len(full_packet))
    
    print(f" 数据包已压缩: {len(payload)} -> {len(compressed_data)} 字节 (节省 {len(payload) - len(compressed_data)} 字节)")
    
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
    """处理旧版Minecraft ping协议 (0xFE)"""
    print(" 处理旧版Ping协议")
    
    if len(data) < 2 or data[0] != 0xFE or data[1] != 0x01:
        return False
    
    print(" 检测到旧版Ping请求")
    
    response_data = config.get_response_data()
    motd = response_data.get("description", {}).get("text", "Minecraft Server")
    online = str(response_data.get("players", {}).get("online", 0))
    max_players = str(response_data.get("players", {}).get("max", 20))
    
    response_str = f"\x00{motd}\x00{online}\x00{max_players}"
    utf16_bytes = response_str.encode('utf-16be')
    response = b'\xff' + struct.pack('>H', len(utf16_bytes)) + utf16_bytes
    
    print(f" 发送旧版Ping响应 (大小: {len(response)} 字节)")
    print(f" 响应十六进制数据:")
    print(hex_dump(response))
    print("-" * 80)
    
    client_socket.send(response)
    return True


def handle_login_handshake(packet_data: bytes, client_socket: socket.socket, id_bytes: int, config: ConfigManager) -> bool:
    """处理登录握手包 (next_state=2)"""
    print(" 登录握手包 (next_state=2)")
    current_pos = id_bytes
    
    try:
        protocol_version, varint_bytes = read_varint(packet_data, current_pos)
        current_pos += varint_bytes
        print(f" 协议版本: {protocol_version}")
    except ValueError:
        print(" 读取协议版本失败")
        return False
    
    try:
        addr_len, varint_bytes = read_varint(packet_data, current_pos)
        current_pos += varint_bytes
        if current_pos + addr_len <= len(packet_data):
            server_address = packet_data[current_pos:current_pos + addr_len].decode('utf-8')
            current_pos += addr_len
            print(f" 服务器地址: {server_address}")
        else:
            print(" 服务器地址数据不完整")
            return False
    except (ValueError, UnicodeDecodeError) as e:
        print(f" 读取服务器地址失败: {e}")
        return False
    
    if current_pos + 2 <= len(packet_data):
        port = struct.unpack('>H', packet_data[current_pos:current_pos + 2])[0]
        current_pos += 2
        print(f" 端口: {port}")
    else:
        print(" 端口数据不完整")
        return False
    
    try:
        next_state, varint_bytes = read_varint(packet_data, current_pos)
        print(f" 下一个状态: {next_state} (登录)")
    except ValueError:
        print(" 读取下一个状态失败")
        return False
    
    print("\n 客户端尝试登录服务器")
    print(" 发送登录断开响应...")
    
    response = create_login_disconnect_response(config)
    full_response = create_packet_with_compression(response, config)
    
    print(f" 响应数据大小: {len(full_response)} 字节")
    print(f" 响应十六进制数据:")
    print(hex_dump(full_response))
    print("-" * 80)
    
    client_socket.send(full_response)
    print(" 登录断开响应已发送")
    return True


def handle_handshake_packet(packet_data: bytes, client_socket: socket.socket, id_bytes: int, config: ConfigManager) -> bool:
    """处理握手包 (next_state=1 或 2) —— 修复：握手时不发送状态响应"""
    current_pos = id_bytes
    
    try:
        protocol_version, varint_bytes = read_varint(packet_data, current_pos)
        current_pos += varint_bytes
        print(f" 协议版本: {protocol_version}")
    except ValueError:
        print(" 读取协议版本失败")
        return False
    
    try:
        addr_len, varint_bytes = read_varint(packet_data, current_pos)
        current_pos += varint_bytes
        if current_pos + addr_len <= len(packet_data):
            server_address = packet_data[current_pos:current_pos + addr_len].decode('utf-8')
            current_pos += addr_len
            print(f" 服务器地址: {server_address}")
        else:
            print(" 服务器地址数据不完整")
            return False
    except (ValueError, UnicodeDecodeError) as e:
        print(f" 读取服务器地址失败: {e}")
        return False
    
    if current_pos + 2 <= len(packet_data):
        port = struct.unpack('>H', packet_data[current_pos:current_pos + 2])[0]
        current_pos += 2
        print(f" 端口: {port}")
    else:
        print(" 端口数据不完整")
        return False
    
    try:
        next_state, varint_bytes = read_varint(packet_data, current_pos)
        print(f" 下一个状态: {next_state} ({'状态' if next_state == 1 else '登录'})")
        
        if next_state == 1:
            # 关键修复：不发送任何数据，仅表示握手成功，等待后续 Status Request
            print(" 握手完成，状态切换为 STATUS，等待状态请求...")
            return True
            
        elif next_state == 2:
            return handle_login_handshake(packet_data, client_socket, id_bytes, config)
            
    except ValueError:
        print(" 读取下一个状态失败")
        return False
    
    return False


def handle_new_protocol(data: bytes, client_socket: socket.socket, config: ConfigManager) -> bool:
    """
    处理新版Minecraft协议 - 解析并处理接收到的数据包
    返回: True 表示需要继续等待数据, False 表示应该关闭连接
    """
    print(" 处理新版协议")
    
    try:
        pos = 0
        
        while pos < len(data):
            try:
                packet_len, varint_bytes = read_varint(data, pos)
                pos += varint_bytes
                
                if pos + packet_len > len(data):
                    print(f" 数据包不完整: 需要 {packet_len} 字节，剩余 {len(data) - pos} 字节")
                    break
                
                packet_data = data[pos:pos + packet_len]
                pos += packet_len
                
                if len(packet_data) > 0:
                    packet_id, id_bytes = read_varint(packet_data, 0)
                    print(f"\n 数据包 ID=0x{packet_id:02x} ({packet_id})")
                    
                    if packet_id == 0x00:
                        # 判断是状态请求还是握手包
                        if len(packet_data) <= id_bytes + 1:
                            # 纯状态请求包 (只有 packet_id)
                            print(" 状态请求包 (0x00)")
                            response = create_response(config)
                            full_response = create_packet_with_compression(response, config)
                            client_socket.send(full_response)
                            print(f" 状态响应已发送 ({len(full_response)} 字节)")
                        else:
                            # 握手包 (包含协议版本、地址等信息)
                            handle_handshake_packet(packet_data, client_socket, id_bytes, config)
                            
                    elif packet_id == 0x01:
                        print(" Ping包 (0x01)")
                        if len(packet_data) >= id_bytes + 8:
                            ping_payload = struct.unpack('>Q', packet_data[id_bytes:id_bytes + 8])[0]
                            print(f"⏱️ Ping payload: {ping_payload}")
                            
                            pong_packet = write_varint(0x01) + struct.pack('>Q', ping_payload)
                            pong_len = write_varint(len(pong_packet))
                            full_pong = pong_len + pong_packet
                            
                            client_socket.send(full_pong)
                            print(f" Pong响应已发送 ({len(full_pong)} 字节)")
                            # Ping/Pong 完成后客户端通常会断开
                            return False
                    else:
                        print(f" 未知数据包ID: 0x{packet_id:02x}")
                        
            except Exception as e:
                print(f" 解析数据包失败: {e}")
                break
        
        return True
        
    except Exception as e:
        print(f" 处理新版协议时出错: {e}")
        import traceback
        traceback.print_exc()
        return False


def handle_client(client_socket: socket.socket, client_address: tuple, config: ConfigManager) -> None:
    """处理客户端连接 - 循环接收和处理数据包"""
    try:
        client_socket.settimeout(10)  # 稍微延长超时
        
        # 收集初始数据
        initial_data = bytearray()
        while True:
            try:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                initial_data.extend(chunk)
                
                # 检查是否收到完整数据包
                if len(initial_data) >= 3:
                    if initial_data[0] == 0xFE:  # 旧版协议
                        break
                    elif initial_data[0] & 0x7F:  # 新版协议
                        try:
                            packet_len, _ = read_varint(bytes(initial_data), 0)
                            if len(initial_data) >= packet_len + len(write_varint(packet_len)):
                                break
                        except:
                            pass
                        
            except socket.timeout:
                break
        
        if not initial_data:
            print(" 未收到数据")
            return
        
        data = bytes(initial_data)
        
        # 获取客户端地址信息（兼容 IPv6 元组格式）
        client_ip = client_address[0]
        client_port = client_address[1]
        if len(client_address) >= 4:  # IPv6 有 flowinfo 和 scopeid
            client_ip = client_address[0]
        
        print(f"\n 收到来自 {client_ip}:{client_port} 的数据包")
        print(f" 数据包大小: {len(data)} 字节")
        print(f" 十六进制数据:")
        print(hex_dump(data))
        print("-" * 80)
        
        # 处理旧版协议
        if len(data) >= 2 and data[0] == 0xFE and data[1] == 0x01:
            handle_legacy_ping(data, client_socket, config)
            return
        
        # 处理新版协议 - 第一次处理
        keep_alive = handle_new_protocol(data, client_socket, config)
        
        # 如果需要保持连接等待 Ping 包
        if keep_alive:
            print(" 等待客户端继续发送数据 (Ping包)...")
            client_socket.settimeout(5)
            
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        print(" 客户端已断开")
                        break
                    
                    print(f" 收到后续数据: {len(chunk)} 字节")
                    print(f" 十六进制数据:")
                    print(hex_dump(chunk))
                    print("-" * 80)
                    
                    # 处理后续数据包
                    keep_alive = handle_new_protocol(chunk, client_socket, config)
                    if not keep_alive:
                        break
                        
                except socket.timeout:
                    print(" 等待超时，客户端可能已完成查询")
                    break
                except Exception as e:
                    print(f" 接收后续数据时出错: {e}")
                    break
        
    except Exception as e:
        print(f" 处理客户端 {client_address} 时出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client_socket.close()
        print(f" 连接已关闭")


class DualStackServer:
    """双栈服务器，同时监听 IPv4 和 IPv6"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.sockets = []
        self.running = True
    
    def start(self):
        """启动双栈服务器"""
        host = self.config.config.get("server", {}).get("host", "0.0.0.0")
        port = self.config.config.get("server", {}).get("port", 25565)
        
        # 尝试创建 IPv6 socket
        try:
            ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            ipv6_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 允许 IPv6 socket 接受 IPv4 连接（在 Windows/Linux 上通常支持）
            try:
                ipv6_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                print(" IPv6 双栈模式已启用 (同时接受 IPv4 连接)")
            except Exception as e:
                print(f" 无法启用 IPv6 双栈模式: {e}")
            
            ipv6_socket.bind(('::', port))
            ipv6_socket.listen(5)
            self.sockets.append(('IPv6', '::', port, ipv6_socket))
            print(f" IPv6 监听 [::]:{port}")
        except Exception as e:
            print(f" 无法创建 IPv6 socket: {e}")
        
        # 尝试创建 IPv4 socket
        try:
            ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ipv4_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ipv4_socket.bind((host, port))
            ipv4_socket.listen(5)
            self.sockets.append(('IPv4', host, port, ipv4_socket))
            print(f" IPv4 监听 {host}:{port}")
        except Exception as e:
            print(f" 无法创建 IPv4 socket: {e}")
        
        if not self.sockets:
            print(" 无法启动任何 socket，服务器退出")
            return
        
        print(f" 当前响应配置:")
        response_data = self.config.get_response_data()
        sample_count = len(response_data.get("players", {}).get("sample", []))
        if sample_count > 0:
            display_response = response_data.copy()
            display_response["players"] = response_data["players"].copy()
            display_response["players"]["sample"] = f"[{sample_count} 个玩家]"
        else:
            display_response = response_data
        print(json.dumps(display_response, ensure_ascii=False, indent=2))
        print(f"\n 提示: 修改 {self.config.config_file} 文件可调整配置")
        print("   修改后重启服务器生效")
        print(f" 压缩阈值: {self.config.get_compression_threshold()} 字节")
        print("\n按 Ctrl+C 停止服务器")
        print("=" * 80)
        
        try:
            while self.running:
                # 使用 select 监听多个 socket
                try:
                    import select
                    read_sockets = [s[3] for s in self.sockets]
                    ready_sockets, _, _ = select.select(read_sockets, [], [], 1.0)
                    
                    for sock in ready_sockets:
                        try:
                            client_socket, client_address = sock.accept()
                            # 获取对应的协议名称
                            proto_name = next((s[0] for s in self.sockets if s[3] == sock), 'Unknown')
                            print(f"\n [{proto_name}] 新连接来自 {client_address[0]}:{client_address[1]}")
                            
                            client_thread = threading.Thread(
                                target=handle_client,
                                args=(client_socket, client_address, self.config)
                            )
                            client_thread.daemon = True
                            client_thread.start()
                        except Exception as e:
                            print(f" 接受连接时出错: {e}")
                            
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    if self.running:
                        print(f" 服务器循环出错: {e}")
                        
        except KeyboardInterrupt:
            print("\n 服务器正在停止...")
        finally:
            self.stop()
    
    def stop(self):
        """停止服务器"""
        self.running = False
        for sock_info in self.sockets:
            try:
                sock_info[3].close()
                print(f" {sock_info[0]} socket 已关闭")
            except:
                pass


def start_server(config: ConfigManager) -> None:
    """启动服务器（使用双栈支持）"""
    server = DualStackServer(config)
    server.start()


def print_usage():
    """打印使用说明"""
    print("""
Minecraft 服务器状态模拟器 (IPv4 + IPv6 双栈支持)
使用方法:
    python server.py              # 使用默认配置文件 test.json
    python server.py config.json  # 使用指定的配置文件

配置文件格式: test.json
    {
        "server": {
            "host": "0.0.0.0",
            "port": 25565,
            "compression_threshold": -1
        },
        "response": {
            "version": {
                "name": "Requires MC 1.8 / 1.21",
                "protocol": 775
            },
            "players": {
                "online": 29983,
                "max": 200000,
                "sample": []
            },
            "description": {
                "text": "MOTD信息"
            },
            "favicon": null
        },
        "login_message": "登录时显示的消息"
    }
    
注意:
    - 如果 IPv6 不可用，会自动回退到 IPv4
    """)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print_usage()
            sys.exit(0)
        config_file = sys.argv[1]
    else:
        config_file = "test.json"
    
    print(f" 使用配置文件: {config_file}")
    config = ConfigManager(config_file)
    start_server(config)
