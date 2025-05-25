#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实用工具模块
"""

import socket
import struct
import re
from datetime import datetime


class NetworkUtils:
    """网络相关工具类"""
    
    @staticmethod
    def format_mac_address(mac_bytes):
        """格式化MAC地址"""
        if isinstance(mac_bytes, bytes):
            return ':'.join(f'{b:02x}' for b in mac_bytes)
        return str(mac_bytes)
    
    @staticmethod
    def format_ip_address(ip_bytes):
        """格式化IP地址"""
        if isinstance(ip_bytes, bytes) and len(ip_bytes) == 4:
            return socket.inet_ntoa(ip_bytes)
        return str(ip_bytes)
    
    @staticmethod
    def get_protocol_name(protocol_number):
        """根据协议号获取协议名称"""
        protocols = {
            1: 'ICMP',
            2: 'IGMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            58: 'ICMPv6',
            89: 'OSPF'
        }
        return protocols.get(protocol_number, f'Protocol-{protocol_number}')
    
    @staticmethod
    def get_port_service(port):
        """根据端口号获取常见服务名称"""
        services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP-Server',
            68: 'DHCP-Client',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S'
        }
        return services.get(port, f'Port-{port}')
    
    @staticmethod
    def is_private_ip(ip_address):
        """判断是否为私有IP地址"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255')
        ]
        
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip_address))[0]
            for start, end in private_ranges:
                start_int = struct.unpack('!I', socket.inet_aton(start))[0]
                end_int = struct.unpack('!I', socket.inet_aton(end))[0]
                if start_int <= ip_int <= end_int:
                    return True
        except:
            pass
        return False


class DataFormatter:
    """数据格式化工具类"""
    
    @staticmethod
    def format_bytes(num_bytes):
        """格式化字节数"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} PB"
    
    @staticmethod
    def format_timestamp(timestamp):
        """格式化时间戳"""
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp)
        else:
            dt = timestamp
        return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    @staticmethod
    def format_hex_dump(data, width=16):
        """格式化十六进制转储"""
        if isinstance(data, str):
            data = data.encode()
        
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<{width*3}}  {ascii_part}')
        
        return '\n'.join(lines)
    
    @staticmethod
    def extract_printable_text(data):
        """提取可打印文本"""
        if isinstance(data, bytes):
            try:
                text = data.decode('utf-8', errors='ignore')
            except:
                text = data.decode('latin-1', errors='ignore')
        else:
            text = str(data)
        
        # 移除不可打印字符
        printable_text = re.sub(r'[^\x20-\x7E\r\n\t]', '.', text)
        return printable_text


class FilterParser:
    """过滤条件解析器"""
    
    @staticmethod
    def parse_filter(filter_string):
        """解析过滤条件字符串"""
        if not filter_string.strip():
            return {}
        
        # 简单的过滤条件解析
        # 支持格式：protocol, host ip, port number, src host ip, dst host ip
        conditions = {}
        
        # 协议过滤，优先匹配更具体的协议
        lower_filter = filter_string.lower()
        protocols = ['https', 'http', 'dns', 'tcp', 'udp', 'icmp', 'arp', 'ip', 'ipv6']
        for proto in protocols:
            if proto in lower_filter:
                conditions['protocol'] = proto.upper()
                break
        
        # IP地址过滤
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, filter_string)
        if ips:
            if 'src host' in filter_string.lower():
                conditions['src_ip'] = ips[0]
            elif 'dst host' in filter_string.lower():
                conditions['dst_ip'] = ips[0]
            else:
                conditions['host'] = ips[0]
        
        # 端口过滤
        port_pattern = r'port\s+(\d+)'
        port_match = re.search(port_pattern, filter_string.lower())
        if port_match:
            conditions['port'] = int(port_match.group(1))
        
        return conditions
    
    @staticmethod
    def apply_filter(packet_info, filter_conditions):
        """应用过滤条件"""
        if not filter_conditions:
            return True
        
        # 检查协议
        if 'protocol' in filter_conditions:
            if packet_info.get('protocol', '').upper() != filter_conditions['protocol']:
                return False
        
        # 检查IP地址
        if 'host' in filter_conditions:
            host_ip = filter_conditions['host']
            if (host_ip != packet_info.get('src_ip', '') and 
                host_ip != packet_info.get('dst_ip', '')):
                return False
        
        if 'src_ip' in filter_conditions:
            if filter_conditions['src_ip'] != packet_info.get('src_ip', ''):
                return False
        
        if 'dst_ip' in filter_conditions:
            if filter_conditions['dst_ip'] != packet_info.get('dst_ip', ''):
                return False
        
        # 检查端口
        if 'port' in filter_conditions:
            port = filter_conditions['port']
            if (port != packet_info.get('src_port', 0) and 
                port != packet_info.get('dst_port', 0)):
                return False
        
        return True


class PacketStatistics:
    """数据包统计工具"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """重置统计"""
        self.total_packets = 0
        self.protocol_counts = {}
        self.size_distribution = {'small': 0, 'medium': 0, 'large': 0}
        self.traffic_by_time = []
        self.src_ips = {}
        self.dst_ips = {}
        self.src_ports = {}
        self.dst_ports = {}
    
    def update(self, packet_info):
        """更新统计信息"""
        self.total_packets += 1
        
        # 协议统计
        protocol = packet_info.get('protocol', 'Unknown')
        self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + 1
        
        # 大小分布统计
        size = packet_info.get('length', 0)
        if size < 100:
            self.size_distribution['small'] += 1
        elif size < 1000:
            self.size_distribution['medium'] += 1
        else:
            self.size_distribution['large'] += 1
        
        # IP地址统计
        src_ip = packet_info.get('src_ip', '')
        if src_ip:
            self.src_ips[src_ip] = self.src_ips.get(src_ip, 0) + 1
        
        dst_ip = packet_info.get('dst_ip', '')
        if dst_ip:
            self.dst_ips[dst_ip] = self.dst_ips.get(dst_ip, 0) + 1
        
        # 端口统计
        src_port = packet_info.get('src_port', 0)
        if src_port:
            self.src_ports[src_port] = self.src_ports.get(src_port, 0) + 1
        
        dst_port = packet_info.get('dst_port', 0)
        if dst_port:
            self.dst_ports[dst_port] = self.dst_ports.get(dst_port, 0) + 1
        
        # 时间流量统计
        current_time = datetime.now().strftime('%H:%M:%S')
        self.traffic_by_time.append((current_time, 1))
        
        # 保持最近100个时间点
        if len(self.traffic_by_time) > 100:
            self.traffic_by_time.pop(0)
    
    def get_top_ips(self, count=10):
        """获取流量最多的IP地址"""
        combined_ips = {}
        
        for ip, src_count in self.src_ips.items():
            combined_ips[ip] = combined_ips.get(ip, 0) + src_count
        
        for ip, dst_count in self.dst_ips.items():
            combined_ips[ip] = combined_ips.get(ip, 0) + dst_count
        
        return sorted(combined_ips.items(), key=lambda x: x[1], reverse=True)[:count]
    
    def get_top_ports(self, count=10):
        """获取使用最多的端口"""
        combined_ports = {}
        
        for port, src_count in self.src_ports.items():
            combined_ports[port] = combined_ports.get(port, 0) + src_count
        
        for port, dst_count in self.dst_ports.items():
            combined_ports[port] = combined_ports.get(port, 0) + dst_count
        
        return sorted(combined_ports.items(), key=lambda x: x[1], reverse=True)[:count]
