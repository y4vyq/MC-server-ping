import socket
import struct
import random
import time
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from collections import OrderedDict, defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import ipaddress

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
            # 移动到末尾（LRU）
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
                    self._cache.popitem(last=False)  # 移除最久未使用
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
    """DNS查询客户端"""

    # DNS 记录类型
    TYPE_A = 1
    TYPE_NS = 2
    TYPE_CNAME = 5
    TYPE_SOA = 6
    TYPE_PTR = 12
    TYPE_MX = 15
    TYPE_TXT = 16
    TYPE_AAAA = 28
    TYPE_SRV = 33

    TYPE_NAMES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
        12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV'
    }

    CLASS_IN = 1

    def __init__(self, dns_servers: List[str] = None, timeout: float = 5.0,
                 max_retries: int = 3, cache_size: int = 128, cache_ttl: int = 300):
        self.dns_servers = dns_servers or ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        self.timeout = timeout
        self.max_retries = max_retries
        self._stats = defaultdict(int)
        self._lock = threading.Lock()
        self._cache = DNSCache(maxsize=cache_size, default_ttl=cache_ttl)

    @staticmethod
    def _generate_transaction_id() -> int:
        """生成唯一事务ID"""
        return random.randint(1, 65535)

    def _build_header(self, transaction_id: int, qdcount: int = 1, rd: int = 1) -> bytes:
        """构建DNS头部（可指定事务ID）"""
        header = struct.pack('>H', transaction_id)
        flags = (rd << 8)  # 递归查询标志
        header += struct.pack('>H', flags)
        header += struct.pack('>HHHH', qdcount, 0, 0, 0)
        return header

    @staticmethod
    def _encode_domain(domain: str) -> bytes:
        """将域名编码为DNS格式"""
        if not domain:
            return b'\x00'
        parts = domain.split('.')
        encoded = b''
        for part in parts:
            if part:
                encoded += bytes([len(part)]) + part.encode()
        encoded += b'\x00'
        return encoded

    @staticmethod
    def _build_question(domain: str, qtype: int = TYPE_SRV, qclass: int = CLASS_IN) -> bytes:
        """构建DNS查询问题部分"""
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
            if length & 0xC0 == 0xC0:          # 压缩指针
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
            name_parts.append(data[offset:offset + length].decode())
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
        for _ in range(ancount):
            name, offset = self._parse_name(response, offset)
            rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset + 10])
            offset += 10

            type_name = self.TYPE_NAMES.get(rtype, f'UNKNOWN({rtype})')

            if rtype == self.TYPE_SRV:
                srv_data, offset = self._parse_srv_record(response, offset)
                answers.append(DNSRecord(name, rtype, type_name, ttl, srv_data))
            elif rtype == self.TYPE_A:
                if rdlength == 4:
                    ip = '.'.join(str(b) for b in response[offset:offset + 4])
                    answers.append(DNSRecord(name, rtype, type_name, ttl, ip))
                offset += rdlength
            elif rtype == self.TYPE_AAAA:
                if rdlength == 16:
                    # 优化：使用 ipaddress 压缩 IPv6 地址
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
                    txt_parts.append(response[pos:pos + length].decode())
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
        """向单个DNS服务器发送查询（使用指定的事务ID）"""
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
        执行DNS查询（内部核心，无缓存），优化重试策略：NXDOMAIN 不重试
        """
        last_error = None
        for attempt in range(self.max_retries):
            for server in self.dns_servers:
                try:
                    transaction_id = self._generate_transaction_id()
                    logger.debug(f"查询 {domain} (类型{self.TYPE_NAMES.get(qtype, qtype)}, "
                                 f"尝试 {attempt+1}/{self.max_retries}, 服务器 {server})")
                    response = self._query_single(domain, qtype, server, transaction_id)
                    answers = self._parse_response(response)
                    if answers:
                        with self._lock:
                            self._stats['successful_queries'] += 1
                        return answers
                    # 空答案不视为失败，直接返回
                    return answers
                except ValueError as e:
                    # NXDOMAIN (rcode 3) 等明确错误不再重试
                    if "域名不存在" in str(e) or "不支持查询类型" in str(e):
                        with self._lock:
                            self._stats['failed_queries'] += 1
                        return []
                    last_error = e
                except Exception as e:
                    last_error = e
                    logger.warning(f"DNS服务器 {server} 查询 {domain} 失败: {e}")
                    with self._lock:
                        self._stats['failed_queries'] += 1
                    continue
            if attempt < self.max_retries - 1:
                time.sleep(0.5 * (attempt + 1))
        # 所有重试后仍失败
        if last_error:
            logger.error(f"查询 {domain} 最终失败: {last_error}")
        return []

    def query(self, domain: str, record_type: int = TYPE_SRV,
              use_cache: bool = True) -> List[DNSRecord]:
        """
        通用DNS查询接口
        :param domain: 域名
        :param record_type: 记录类型（例如 DNSQuery.TYPE_A）
        :param use_cache: 是否使用缓存
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
                # 缓存成功结果，TTL 取记录中最小的值（最大不超过默认值）
                ttl = min(r.ttl for r in records) if records else self._cache.default_ttl
                self._cache.set(key, records, ttl)
            return records
        return self._query_dns(domain, record_type)

    # 保留特定方法方便调用
    def query_srv(self, domain: str, use_cache: bool = True) -> List[DNSRecord]:
        """查询SRV记录"""
        return self.query(domain, self.TYPE_SRV, use_cache)

    def query_any(self, domain: str, record_type: int, use_cache: bool = True) -> List[DNSRecord]:
        """查询任意类型记录（别名，兼容旧代码）"""
        return self.query(domain, record_type, use_cache)

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
        })
        # 确保 cache_hits 和 cache_misses 存在
        stats.setdefault('cache_hits', 0)
        stats.setdefault('cache_misses', 0)
        return stats

    def clear_cache(self):
        self._cache.clear()
        logger.info("DNS缓存已清除")

    def close(self):
        """清理资源（如有需要）"""
        self.clear_cache()


class MinecraftServerResolver:
    """Minecraft服务器解析器"""
    def __init__(self, dns_query: DNSQuery = None):
        self.dns = dns_query or DNSQuery()

    def resolve_server(self, domain: str) -> Tuple[Optional[str], Optional[int]]:
        """解析Minecraft服务器地址，返回 (host, port) 或 (None, None)"""
        try:
            srv_domain = f'_minecraft._tcp.{domain}'
            answers = self.dns.query(srv_domain, DNSQuery.TYPE_SRV)

            if answers:
                sorted_records = sorted(answers,
                                        key=lambda x: (x.data.priority, -x.data.weight))
                best = sorted_records[0]
                logger.info(f" 找到 SRV 记录: {best.data.target}:{best.data.port}")
                return best.data.target, best.data.port

            # 如果没有SRV记录，尝试直接解析A记录
            logger.info(f" 未找到SRV记录，尝试直接解析 {domain}")
            a_records = self.dns.query(domain, DNSQuery.TYPE_A)
            if a_records:
                return domain, 25565
            return None, None
        except Exception as e:
            logger.error(f"解析 {domain} 失败: {e}")
            return None, None

    def resolve_multiple(self, domains: List[str]) -> Dict[str, Dict]:
        """批量解析多个Minecraft服务器"""
        results = {}
        for domain in domains:
            host, port = self.resolve_server(domain)
            if host:
                results[domain] = {'host': host, 'port': port, 'status': 'online'}
            else:
                results[domain] = {'status': 'offline'}
        return results


class DNSBenchmark:
    """DNS性能基准测试（优化成功判断逻辑）"""
    def __init__(self, domains: List[str] = None):
        self.domains = domains or [
            'google.com', 'github.com', 'stackoverflow.com',
            'amazon.com', 'wikipedia.org', 'www.baidu.com'
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
                    # 仅当返回非空答案时才计为成功
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
