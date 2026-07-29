import socket
import struct
import random
import time
from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass
from collections import OrderedDict, defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import ipaddress
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    """DNS记录数据类"""
    name: str
    type: int
    type_name: str
    ttl: int
    data: Any

    def __str__(self):
        return f"{self.name} {self.type_name} {self.data}"


@dataclass
class SRVRecord:
    """SRV记录数据类"""
    priority: int
    weight: int
    port: int
    target: str

    def __str__(self):
        return f"{self.target}:{self.port} (优先级:{self.priority}, 权重:{self.weight})"


class DNSCache:
    """线程安全的 LRU 缓存，支持 TTL（秒）过期"""
    def __init__(self, maxsize: int = 128, default_ttl: int = 300):
        self.maxsize = maxsize
        self.default_ttl = default_ttl
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key) -> Optional[List[DNSRecord]]:
        with self._lock:
            if key not in self._cache:
                return None
            entry = self._cache[key]
            if time.monotonic() - entry['time'] > entry['ttl']:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return entry['records']

    def set(self, key, records: List[DNSRecord], ttl: Optional[int] = None):
        if ttl is None:
            ttl = self.default_ttl
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self.maxsize:
                    self._cache.popitem(last=False)
            self._cache[key] = {
                'records': records,
                'time': time.monotonic(),
                'ttl': ttl
            }

    def clear(self):
        with self._lock:
            self._cache.clear()

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                'size': len(self._cache),
                'maxsize': self.maxsize
            }


class DNSQuery:
    """DNS查询客户端（线程安全，优化的缓存和异常处理，支持CNAME追踪）"""
    
    # DNS记录类型常量
    TYPE_A = 1
    TYPE_NS = 2
    TYPE_CNAME = 5
    TYPE_SOA = 6
    TYPE_PTR = 12
    TYPE_MX = 15
    TYPE_TXT = 16
    TYPE_AAAA = 28
    TYPE_SRV = 33
    
    # 自动生成类型名称映射
    TYPE_NAMES = {
        TYPE_A: 'A', TYPE_NS: 'NS', TYPE_CNAME: 'CNAME',
        TYPE_SOA: 'SOA', TYPE_PTR: 'PTR', TYPE_MX: 'MX',
        TYPE_TXT: 'TXT', TYPE_AAAA: 'AAAA', TYPE_SRV: 'SRV'
    }
    
    CLASS_IN = 1
    DEFAULT_DNS = ['8.8.8.8', '1.1.1.1', '114.114.114.114']
    
    def __init__(self, dns_servers: Optional[List[str]] = None, 
                 timeout: float = 5.0,
                 max_retries: int = 3, 
                 cache_size: int = 128, 
                 cache_ttl: int = 300,
                 max_cname_depth: int = 10):
        """
        DNS查询客户端初始化
        
        :param dns_servers: DNS服务器列表，不传则从文件或默认值读取
        :param timeout: 查询超时时间（秒）
        :param max_retries: 最大重试次数
        :param cache_size: 缓存最大条目数
        :param cache_ttl: 缓存过期时间（秒）
        :param max_cname_depth: CNAME追踪的最大深度，防止循环引用
        """
        # 确定DNS服务器列表
        if dns_servers is not None:
            self.dns_servers = dns_servers
        else:
            self.dns_servers = self._load_dns_servers_from_file()
        
        # 备选方案
        if not self.dns_servers:
            self.dns_servers = self.DEFAULT_DNS
        
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_cname_depth = max_cname_depth
        self._stats = defaultdict(int)
        self._lock = threading.Lock()
        self._cache = DNSCache(maxsize=cache_size, default_ttl=cache_ttl)
    
    def _load_dns_servers_from_file(self) -> List[str]:
        """从配置文件加载DNS服务器列表"""
        # 如果已经加载过，直接返回缓存的结果
        if hasattr(self, '_cached_servers'):
            return self._cached_servers
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, 'dns_servers.txt')
        
        try:
            with open(config_path, 'r') as f:
                servers = [
                    line.strip() 
                    for line in f 
                    if line.strip() and not line.startswith('#')
                ]
            
            if servers:
                return servers
            else:
                return []
                
        except FileNotFoundError:
            return []
        except Exception as e:
            return []

    @staticmethod
    def _generate_transaction_id() -> int:
        return random.randint(1, 65535)

    def _build_header(self, transaction_id: int, qdcount: int = 1, rd: int = 1) -> bytes:
        header = struct.pack('>H', transaction_id)
        flags = (rd << 8)
        header += struct.pack('>H', flags)
        header += struct.pack('>HHHH', qdcount, 0, 0, 0)
        return header

    @staticmethod
    def _encode_domain(domain: str) -> bytes:
        if not domain:
            return b'\x00'
        parts = domain.split('.')
        encoded = b''
        for part in parts:
            if part:
                encoded += bytes([len(part)]) + part.encode('ascii', errors='replace')
        encoded += b'\x00'
        return encoded

    @staticmethod
    def _build_question(domain: str, qtype: int = TYPE_SRV, qclass: int = CLASS_IN) -> bytes:
        return DNSQuery._encode_domain(domain) + struct.pack('>HH', qtype, qclass)

    def _parse_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """解析DNS域名（支持压缩指针）"""
        name_parts = []
        jumped = False
        original_offset = offset

        while True:
            if offset >= len(data):
                raise ValueError("偏移量超出范围")

            length = data[offset]
            if length & 0xC0 == 0xC0:
                if not jumped:
                    original_offset = offset + 2
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                offset = pointer
                jumped = True
                continue
            if length == 0:
                offset += 1
                break
            offset += 1
            if offset + length > len(data):
                raise ValueError("域名标签长度超出范围")
            try:
                name_parts.append(data[offset:offset + length].decode('ascii'))
            except UnicodeDecodeError:
                name_parts.append(data[offset:offset + length].decode('ascii', errors='replace'))
            offset += length

        if not jumped:
            return '.'.join(name_parts), offset
        return '.'.join(name_parts), original_offset

    def _parse_srv_record(self, data: bytes, offset: int) -> Tuple[SRVRecord, int]:
        """解析SRV记录"""
        priority, weight, port = struct.unpack('>HHH', data[offset:offset + 6])
        offset += 6
        target, offset = self._parse_name(data, offset)
        return SRVRecord(priority, weight, port, target), offset

    def _parse_response(self, response: bytes) -> List[DNSRecord]:
        """解析DNS响应"""
        if len(response) < 12:
            raise ValueError("无效的DNS响应")

        header = response[:12]
        trans_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', header)

        rcode = flags & 0x0F
        if rcode != 0:
            error_messages = {
                1: "格式错误", 2: "服务器失败", 3: "域名不存在",
                4: "不支持查询类型", 5: "拒绝访问"
            }
            raise ValueError(f"DNS错误: {error_messages.get(rcode, f'未知错误 ({rcode})')}")

        offset = 12
        # 跳过Question部分
        for _ in range(qdcount):
            _, offset = self._parse_name(response, offset)
            offset += 4

        answers = []
        # 解析所有Answer记录
        for _ in range(ancount):
            name, offset = self._parse_name(response, offset)
            rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset + 10])
            offset += 10

            type_name = self.TYPE_NAMES.get(rtype, f'UNKNOWN({rtype})')

            if rtype == self.TYPE_SRV:
                srv_data, offset = self._parse_srv_record(response, offset)
                answers.append(DNSRecord(name, rtype, type_name, ttl, srv_data))
            elif rtype == self.TYPE_CNAME:
                cname, offset = self._parse_name(response, offset)
                answers.append(DNSRecord(name, rtype, type_name, ttl, cname))
            elif rtype == self.TYPE_A:
                if rdlength == 4:
                    ip = '.'.join(str(b) for b in response[offset:offset + 4])
                    answers.append(DNSRecord(name, rtype, type_name, ttl, ip))
                offset += rdlength
            elif rtype == self.TYPE_AAAA:
                if rdlength == 16:
                    raw = response[offset:offset + 16]
                    ip = str(ipaddress.IPv6Address(bytes(raw)))
                    answers.append(DNSRecord(name, rtype, type_name, ttl, ip))
                offset += rdlength
            elif rtype == self.TYPE_TXT:
                txt_parts = []
                pos = offset
                while pos < offset + rdlength:
                    length = response[pos]
                    pos += 1
                    txt_parts.append(response[pos:pos + length].decode('ascii', errors='replace'))
                    pos += length
                answers.append(DNSRecord(name, rtype, type_name, ttl, ''.join(txt_parts)))
                offset += rdlength
            elif rtype == self.TYPE_MX:
                preference, = struct.unpack('>H', response[offset:offset + 2])
                offset += 2
                exchange, offset = self._parse_name(response, offset)
                answers.append(DNSRecord(name, rtype, type_name, ttl,
                                         {'preference': preference, 'exchange': exchange}))
            else:
                offset += rdlength

        with self._lock:
            self._stats['total_queries'] += 1
            self._stats['total_answers'] += len(answers)

        return answers

    def _query_single(self, domain: str, qtype: int, dns_server: str,
                      transaction_id: int) -> bytes:
        """向单个DNS服务器发送查询"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            header = self._build_header(transaction_id, qdcount=1, rd=1)
            question = self._build_question(domain, qtype)
            query = header + question

            sock.sendto(query, (dns_server, 53))
            response, _ = sock.recvfrom(4096)

            resp_id, = struct.unpack('>H', response[:2])
            if resp_id != transaction_id:
                raise ValueError("事务ID不匹配")
            return response
        finally:
            sock.close()

    def _query_dns(self, domain: str, qtype: int) -> List[DNSRecord]:
        """
        执行DNS查询（内部核心，支持CNAME追踪）
        """
        last_error = None
        queried_domains = set()  # 防止CNAME循环
        current_domain = domain
        all_answers = []
        depth = 0

        while depth < self.max_cname_depth:
            if current_domain in queried_domains:
                logger.warning(f"检测到CNAME循环引用: {current_domain}")
                break
            queried_domains.add(current_domain)

            # 对当前域名发起查询
            raw_response = None
            for attempt in range(self.max_retries):
                for server in self.dns_servers:
                    try:
                        transaction_id = self._generate_transaction_id()
                        logger.debug(f"查询 {current_domain} (类型{self.TYPE_NAMES.get(qtype, qtype)}, "
                                     f"CNAME深度{depth}, 尝试 {attempt+1}/{self.max_retries}, 服务器 {server})")
                        raw_response = self._query_single(current_domain, qtype, server, transaction_id)
                        break
                    except ValueError as e:
                        if "域名不存在" in str(e) or "不支持查询类型" in str(e):
                            with self._lock:
                                self._stats['failed_queries'] += 1
                            return all_answers if all_answers else []
                        last_error = e
                    except Exception as e:
                        last_error = e
                        logger.warning(f"DNS服务器 {server} 查询 {current_domain} 失败: {e}")
                        with self._lock:
                            self._stats['failed_queries'] += 1
                        continue
                if raw_response:
                    break
                if attempt < self.max_retries - 1:
                    time.sleep(0.5 * (attempt + 1))

            if raw_response is None:
                if last_error:
                    logger.error(f"查询 {current_domain} 最终失败: {last_error}")
                return all_answers if all_answers else []

            # 解析响应
            answers = self._parse_response(raw_response)
            if not answers:
                return all_answers if all_answers else []

            # 分离CNAME记录和其他记录
            cname_records = [r for r in answers if r.type == self.TYPE_CNAME]
            other_records = [r for r in answers if r.type != self.TYPE_CNAME]

            # 添加到总结果中
            all_answers.extend(answers)

            # 如果有目标类型的记录，说明CNAME链已经解析完成
            target_records = [r for r in other_records if r.type == qtype]
            if target_records:
                with self._lock:
                    self._stats['successful_queries'] += 1
                return all_answers

            # 如果有CNAME记录，继续追踪
            if cname_records:
                # 取第一个CNAME记录（通常只有一个）
                current_domain = cname_records[0].data
                depth += 1
                logger.info(f"发现CNAME记录: {answers[0].name} -> {current_domain}，继续追踪")
                continue
            else:
                # 没有CNAME也没有目标类型记录，返回已有答案
                return all_answers

        if depth >= self.max_cname_depth:
            logger.warning(f"CNAME追踪达到最大深度 {self.max_cname_depth}，停止追踪")

        with self._lock:
            if all_answers:
                self._stats['successful_queries'] += 1
            else:
                self._stats['failed_queries'] += 1
        return all_answers

    def query(self, domain: str, record_type: int = TYPE_SRV,
              use_cache: bool = True) -> List[DNSRecord]:
        """
        通用DNS查询接口
        :param domain: 域名
        :param record_type: 记录类型
        :param use_cache: 是否使用缓存
        :return: 返回所有相关记录（包括CNAME链中的记录）
        """
        if use_cache:
            key = (domain, record_type)
            cached = self._cache.get(key)
            if cached is not None:
                with self._lock:
                    self._stats['cache_hits'] += 1
                return cached
            with self._lock:
                self._stats['cache_misses'] += 1
            records = self._query_dns(domain, record_type)
            if records:
                # 取最终目标记录的TTL（不含CNAME中间记录）
                final_records = [r for r in records if r.type == record_type]
                ttl = min(r.ttl for r in final_records) if final_records else self._cache.default_ttl
                self._cache.set(key, records, ttl)
            return records
        return self._query_dns(domain, record_type)

    def query_srv(self, domain: str, use_cache: bool = True) -> List[DNSRecord]:
        """查询SRV记录"""
        return self.query(domain, self.TYPE_SRV, use_cache)

    def query_a(self, domain: str, use_cache: bool = True) -> List[DNSRecord]:
        """查询A记录"""
        return self.query(domain, self.TYPE_A, use_cache)

    def query_aaaa(self, domain: str, use_cache: bool = True) -> List[DNSRecord]:
        """查询AAAA记录"""
        return self.query(domain, self.TYPE_AAAA, use_cache)

    def query_any(self, domain: str, record_type: int, use_cache: bool = True) -> List[DNSRecord]:
        """查询任意类型记录（别名，兼容旧代码）"""
        return self.query(domain, record_type, use_cache)

    def query_with_cname_info(self, domain: str, record_type: int = TYPE_A) -> Dict[str, Any]:
        """
        查询并返回CNAME相关信息
        
        :return: {
            'final_domain': '最终域名',
            'cname_chain': ['别名1', '别名2', ...],  # CNAME链
            'records': [DNSRecord, ...]  # 所有相关记录
        }
        """
        records = self.query(domain, record_type, use_cache=False)
        
        cname_chain = []
        current = domain
        for r in records:
            if r.type == self.TYPE_CNAME and r.name == current:
                cname_chain.append(r.data)
                current = r.data
        
        target_records = [r for r in records if r.type == record_type]
        
        return {
            'final_domain': current if target_records else domain,
            'cname_chain': cname_chain,
            'records': target_records
        }

    def query_batch(self, domains: List[str], record_type: int = TYPE_SRV,
                    max_workers: int = 10) -> Dict[str, List[DNSRecord]]:
        """批量查询多个域名"""
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {
                executor.submit(self.query, domain, record_type): domain
                for domain in domains
            }
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    results[domain] = future.result()
                except Exception as e:
                    logger.error(f"查询 {domain} 失败: {e}")
                    results[domain] = []
        return results

    def get_stats(self) -> Dict[str, Any]:
        stats = dict(self._stats)
        cache_stats = self._cache.stats()
        stats.update({
            'cache_size': cache_stats['size'],
            'cache_maxsize': cache_stats['maxsize'],
            'dns_servers': self.dns_servers,
            'timeout': self.timeout,
            'max_cname_depth': self.max_cname_depth,
        })
        stats.setdefault('cache_hits', 0)
        stats.setdefault('cache_misses', 0)
        return stats

    def clear_cache(self):
        self._cache.clear()
        logger.info("DNS缓存已清除")

    def close(self):
        self.clear_cache()


class MinecraftServerResolver:
    """Minecraft服务器解析器（支持RFC 2782加权随机选择和CNAME追踪）"""
    def __init__(self, dns_query: DNSQuery = None, force_srv: bool = False):
        """
        :param dns_query: DNS 查询客户端实例
        :param force_srv: 是否强制仅使用 SRV 解析（不回退到 A 记录）
        """
        self.dns = dns_query or DNSQuery()
        self.force_srv = force_srv

    @staticmethod
    def _is_ip_address(domain: str) -> bool:
        """判断输入是否为纯 IP 地址（IPv4 或 IPv6）"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    @staticmethod
    def _weighted_random_choice(candidates: List[DNSRecord]) -> DNSRecord:
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

    def resolve_server(self, domain: str, force_srv: Optional[bool] = None) -> Tuple[Optional[str], Optional[int]]:
        """
        解析Minecraft服务器地址，返回 (host, port) 或 (None, None)
        
        :param domain: 域名或 IP 地址
        :param force_srv: 是否强制仅使用 SRV 解析。若为 None，则使用实例默认值 self.force_srv
        """
        if force_srv is None:
            force_srv = self.force_srv

        # 如果已经是 IP 地址，直接返回，端口默认 25565
        if self._is_ip_address(domain):
            logger.info(f"输入为 IP 地址，直接使用: {domain}:25565")
            return domain, 25565

        try:
            srv_domain = f'_minecraft._tcp.{domain}'
            answers = self.dns.query(srv_domain, DNSQuery.TYPE_SRV)

            if answers:
                srv_records = [r for r in answers if r.type == DNSQuery.TYPE_SRV]
                if not srv_records:
                    logger.warning(f"查询 {srv_domain} 未返回有效的SRV记录")
                else:
                    priority_groups = {}
                    for record in srv_records:
                        priority_groups.setdefault(record.data.priority, []).append(record)
                    best_priority = min(priority_groups.keys())
                    candidates = priority_groups[best_priority]
                    chosen = self._weighted_random_choice(candidates)

                    cname_records = [r for r in answers if r.type == DNSQuery.TYPE_CNAME]
                    if cname_records:
                        logger.info(f"✅ 通过CNAME解析找到 SRV 记录: {chosen.data.target}:{chosen.data.port} "
                                    f"(优先级:{chosen.data.priority}, 权重:{chosen.data.weight})")
                    else:
                        logger.info(f"✅ 找到 SRV 记录: {chosen.data.target}:{chosen.data.port} "
                                    f"(优先级:{chosen.data.priority}, 权重:{chosen.data.weight})")
                    return chosen.data.target, chosen.data.port

            # 无 SRV 记录时的处理
            if force_srv:
                logger.info(f"强制 SRV 解析，未找到 SRV 记录，放弃解析")
                return None, None

            # 回退到 A 记录
            logger.info(f"ℹ️ 未找到SRV记录，尝试直接解析 {domain}")
            a_records = self.dns.query(domain, DNSQuery.TYPE_A)
            if a_records:
                # 取第一个 A 记录
                ip = a_records[0].data if a_records[0].type == DNSQuery.TYPE_A else a_records[-1].data
                return domain, 25565
            return None, None
        except Exception as e:
            logger.error(f"解析 {domain} 失败: {e}")
            return None, None

    def resolve_server_detailed(self, domain: str, force_srv: Optional[bool] = None) -> Dict[str, Any]:
        """详细解析，支持 force_srv 控制和 IP 直连"""
        if force_srv is None:
            force_srv = self.force_srv

        if self._is_ip_address(domain):
            return {
                'host': domain,
                'port': 25565,
                'final_domain': domain,
                'cname_chain': [],
                'records': [],
                'status': 'resolved_ip'
            }

        try:
            srv_domain = f'_minecraft._tcp.{domain}'
            cname_info = self.dns.query_with_cname_info(srv_domain, DNSQuery.TYPE_SRV)

            if cname_info['records']:
                srv_records = cname_info['records']
                if len(srv_records) == 1:
                    chosen = srv_records[0]
                else:
                    priority_groups = {}
                    for record in srv_records:
                        priority_groups.setdefault(record.data.priority, []).append(record)
                    best_priority = min(priority_groups.keys())
                    candidates = priority_groups[best_priority]
                    chosen = self._weighted_random_choice(candidates)

                host, port = chosen.data.target, chosen.data.port
                return {
                    'host': host,
                    'port': port,
                    'final_domain': cname_info['final_domain'],
                    'cname_chain': cname_info['cname_chain'],
                    'records': srv_records,
                    'status': 'resolved'
                }

            if force_srv:
                return {'status': 'failed', 'error': '强制 SRV 解析失败'}

            # 回退到 A 记录
            a_cname_info = self.dns.query_with_cname_info(domain, DNSQuery.TYPE_A)
            if a_cname_info['records']:
                ip = a_cname_info['records'][0].data
                return {
                    'host': domain,
                    'port': 25565,
                    'final_domain': a_cname_info['final_domain'],
                    'cname_chain': a_cname_info['cname_chain'],
                    'records': a_cname_info['records'],
                    'status': 'resolved_via_a'
                }
            return {'status': 'failed', 'error': '无法解析服务器地址'}
        except Exception as e:
            logger.error(f"详细解析 {domain} 失败: {e}")
            return {'status': 'failed', 'error': str(e)}


class DNSBenchmark:
    """DNS性能基准测试"""
    def __init__(self, domains: List[str] = None):
        self.domains = domains or [
            'google.com', 'github.com', 'stackoverflow.com',
            'amazon.com', 'wikipedia.org'
        ]

    def benchmark(self, dns_servers: List[str]) -> Dict[str, Dict]:
        results = {}
        for server in dns_servers:
            dns = DNSQuery([server], timeout=3.0, max_retries=2)
            stats = {'success_count': 0, 'total_time': 0.0, 'failures': 0}

            for domain in self.domains:
                try:
                    start = time.time()
                    answers = dns.query(domain, DNSQuery.TYPE_A, use_cache=False)
                    elapsed = time.time() - start
                    if answers:
                        stats['success_count'] += 1
                        stats['total_time'] += elapsed
                    else:
                        stats['failures'] += 1
                except Exception:
                    stats['failures'] += 1

            if stats['success_count'] > 0:
                stats['avg_time_ms'] = (stats['total_time'] / stats['success_count']) * 1000
            else:
                stats['avg_time_ms'] = float('inf')
            results[server] = stats
        return results


if __name__ == "__main__":
    # 示例1：基本使用
    print("=== 基本解析示例 ===")
    dns_client = DNSQuery()
    resolver = MinecraftServerResolver(dns_client)
    
    # 测试CNAME追踪
    print("\n测试CNAME记录解析:")
    # 查询常见的CNAME记录
    cname_info = dns_client.query_with_cname_info("www.github.com", DNSQuery.TYPE_A)
    print(f"最终域名: {cname_info['final_domain']}")
    print(f"CNAME链: {' -> '.join(['www.github.com'] + cname_info['cname_chain'])}")
    for record in cname_info['records']:
        print(f"  {record}")

    # 示例2：Minecraft服务器解析
    print("\n=== Minecraft服务器解析 ===")
    test_domains = ["hypixel.net", "mc.hypixel.net"]
    for domain in test_domains:
        print(f"\n解析 {domain}:")
        host, port = resolver.resolve_server(domain)
        if host:
            print(f"  服务器: {host}:{port}")
        else:
            print(f"  解析失败")
        
        # 详细解析
        detailed = resolver.resolve_server_detailed(domain)
        print(f"  详细: {detailed}")

    # 示例3：批量查询
    print("\n=== 批量查询 ===")
    domains = ["google.com", "github.com", "youtube.com"]
    results = dns_client.query_batch(domains, DNSQuery.TYPE_A)
    for domain, records in results.items():
        ips = [r.data for r in records if r.type == DNSQuery.TYPE_A]
        print(f"  {domain}: {ips}")

    # 示例4：性能统计
    print("\n=== 查询统计 ===")
    stats = dns_client.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
