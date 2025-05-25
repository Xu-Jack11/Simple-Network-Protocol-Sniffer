import time
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR


class PacketAnalyzer:
    """数据包分析器"""
    
    def __init__(self):
        self.protocol_parsers = {
            'Ether': self._parse_ethernet,
            'IP': self._parse_ip,
            'IPv6': self._parse_ipv6,
            'TCP': self._parse_tcp,
            'UDP': self._parse_udp,
            'ICMP': self._parse_icmp,
            'ARP': self._parse_arp,
            'DNS': self._parse_dns,
            'HTTP': self._parse_http
        }
        
    def analyze_packet(self, packet):
        """分析数据包，提取详细信息"""
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'length': len(packet),
            'src_ip': '',
            'dst_ip': '',
            'src_port': '',
            'dst_port': '',
            'protocol': 'Unknown',
            'info': '',
            'layers': {},
            'raw_packet': packet
        }
        
        # 分析各层协议
        self._analyze_layers(packet, packet_info)
        
        # 生成简要信息
        self._generate_summary_info(packet_info)
        
        return packet_info
        
    def _analyze_layers(self, packet, packet_info):
        """分析数据包的各层协议"""
        layer_index = 0
        current_layer = packet
        
        while current_layer:
            layer_name = current_layer.__class__.__name__
            
            # 解析当前层
            if layer_name in self.protocol_parsers:
                try:
                    layer_info = self.protocol_parsers[layer_name](current_layer)
                    packet_info['layers'][f"{layer_index:02d}_{layer_name}"] = layer_info
                    
                    # 更新主要信息
                    self._update_main_info(packet_info, layer_name, layer_info)
                except Exception as e:
                    print(f"解析{layer_name}层时出错: {str(e)}")
                    
            layer_index += 1
            current_layer = current_layer.payload if hasattr(current_layer, 'payload') else None
            
            # 避免无限循环
            if layer_index > 10:
                break
                
    def _parse_ethernet(self, layer):
        """解析以太网层"""
        return {
            '源MAC地址': getattr(layer, 'src', ''),
            '目的MAC地址': getattr(layer, 'dst', ''),
            '类型': f"0x{getattr(layer, 'type', 0):04x}"
        }
        
    def _parse_ip(self, layer):
        """解析IP层"""
        flags_str = []
        try:
            # 安全地获取flags属性
            ip_flags = getattr(layer, 'flags', 0)
            if ip_flags & 0x02:  # DF flag
                flags_str.append("DF")
            if ip_flags & 0x01:  # MF flag
                flags_str.append("MF")
        except (AttributeError, TypeError):
            # 如果无法获取flags，设为空
            flags_str = []
            
        return {
            '版本': getattr(layer, 'version', 0),
            '头部长度': f"{getattr(layer, 'ihl', 0) * 4} bytes",
            '服务类型': f"0x{getattr(layer, 'tos', 0):02x}",
            '总长度': f"{getattr(layer, 'len', 0)} bytes",
            '标识': f"0x{getattr(layer, 'id', 0):04x}",
            '标志': ", ".join(flags_str) if flags_str else "无",
            '片偏移': getattr(layer, 'frag', 0),
            '生存时间': getattr(layer, 'ttl', 0),
            '协议': getattr(layer, 'proto', 0),
            '头部校验和': f"0x{getattr(layer, 'chksum', 0):04x}",
            '源IP地址': getattr(layer, 'src', ''),
            '目的IP地址': getattr(layer, 'dst', '')
        }
        
    def _parse_ipv6(self, layer):
        """解析IPv6层"""
        return {
            '版本': getattr(layer, 'version', 0),
            '流量类': getattr(layer, 'tc', 0),
            '流标签': getattr(layer, 'fl', 0),
            '负载长度': f"{getattr(layer, 'plen', 0)} bytes",
            '下一个头部': getattr(layer, 'nh', 0),
            '跳数限制': getattr(layer, 'hlim', 0),
            '源IPv6地址': getattr(layer, 'src', ''),
            '目的IPv6地址': getattr(layer, 'dst', '')
        }
        
    def _parse_tcp(self, layer):
        """解析TCP层"""
        flags = []
        try:
            # 安全地获取flags属性
            tcp_flags = getattr(layer, 'flags', 0)
            if tcp_flags & 0x01:  # FIN
                flags.append("FIN")
            if tcp_flags & 0x02:  # SYN
                flags.append("SYN")
            if tcp_flags & 0x04:  # RST
                flags.append("RST")
            if tcp_flags & 0x08:  # PSH
                flags.append("PSH")
            if tcp_flags & 0x10:  # ACK
                flags.append("ACK")
            if tcp_flags & 0x20:  # URG
                flags.append("URG")
        except (AttributeError, TypeError):
            # 如果无法获取flags，保持flags列表为空
            flags = []
            
        return {
            '源端口': getattr(layer, 'sport', 0),
            '目的端口': getattr(layer, 'dport', 0),
            '序列号': getattr(layer, 'seq', 0),
            '确认号': getattr(layer, 'ack', 0),
            '数据偏移': f"{getattr(layer, 'dataofs', 0) * 4} bytes",
            '标志': ", ".join(flags) if flags else "无",
            '窗口大小': getattr(layer, 'window', 0),
            '校验和': f"0x{getattr(layer, 'chksum', 0):04x}",
            '紧急指针': getattr(layer, 'urgptr', 0)
        }
        
    def _parse_udp(self, layer):
        """解析UDP层"""
        return {
            '源端口': getattr(layer, 'sport', 0),
            '目的端口': getattr(layer, 'dport', 0),
            '长度': f"{getattr(layer, 'len', 0)} bytes",
            '校验和': f"0x{getattr(layer, 'chksum', 0):04x}"
        }
        
    def _parse_icmp(self, layer):
        """解析ICMP层"""
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem"
        }
        
        return {
            '类型': f"{getattr(layer, 'type', 0)} ({icmp_types.get(getattr(layer, 'type', 0), 'Unknown')})",
            '代码': getattr(layer, 'code', 0),
            '校验和': f"0x{getattr(layer, 'chksum', 0):04x}",
            '标识符': getattr(layer, 'id', 'N/A'),
            '序列号': getattr(layer, 'seq', 'N/A')
        }
        
    def _parse_arp(self, layer):
        """解析ARP层"""
        op_codes = {
            1: "ARP请求",
            2: "ARP应答",
            3: "RARP请求",
            4: "RARP应答"
        }
        
        return {
            '硬件类型': getattr(layer, 'hwtype', 0),
            '协议类型': f"0x{getattr(layer, 'ptype', 0):04x}",
            '硬件地址长度': getattr(layer, 'hwlen', 0),
            '协议地址长度': getattr(layer, 'plen', 0),
            '操作码': f"{getattr(layer, 'op', 0)} ({op_codes.get(getattr(layer, 'op', 0), 'Unknown')})",
            '发送方MAC': getattr(layer, 'hwsrc', ''),
            '发送方IP': getattr(layer, 'psrc', ''),
            '目标MAC': getattr(layer, 'hwdst', ''),
            '目标IP': getattr(layer, 'pdst', '')
        }
        
    def _parse_dns(self, layer):
        """解析DNS层"""
        dns_info = {
            '事务ID': f"0x{getattr(layer, 'id', 0):04x}",
            '标志': f"0x{getattr(layer, 'flags', 0):04x}",
            '问题数': getattr(layer, 'qdcount', 0),
            '回答数': getattr(layer, 'ancount', 0),
            '权威记录数': getattr(layer, 'nscount', 0),
            '附加记录数': getattr(layer, 'arcount', 0)
        }
        
        # 解析查询记录
        try:
            if hasattr(layer, 'qd') and layer.qd:
                queries = []
                qd = layer.qd if isinstance(layer.qd, list) else [layer.qd]
                for query in qd:
                    if hasattr(query, 'qname'):
                        qname = query.qname.decode() if isinstance(query.qname, bytes) else str(query.qname)
                        queries.append(f"{qname} ({getattr(query, 'qtype', 'Unknown')})")
                if queries:
                    dns_info['查询'] = "; ".join(queries)
        except Exception:
            pass
                
        # 解析回答记录
        try:
            if hasattr(layer, 'an') and layer.an:
                answers = []
                an = layer.an if isinstance(layer.an, list) else [layer.an]
                for answer in an:
                    if hasattr(answer, 'rrname') and hasattr(answer, 'rdata'):
                        rrname = answer.rrname.decode() if isinstance(answer.rrname, bytes) else str(answer.rrname)
                        answers.append(f"{rrname} -> {answer.rdata}")
                if answers:
                    dns_info['回答'] = "; ".join(answers)
        except Exception:
            pass
                
        return dns_info
        
    def _parse_http(self, layer):
        """解析HTTP层"""
        http_info = {}
        
        try:
            if hasattr(layer, 'Method'):
                # HTTP请求
                http_info['类型'] = 'HTTP请求'
                method = layer.Method.decode() if isinstance(layer.Method, bytes) else str(layer.Method)
                http_info['方法'] = method
                
                if hasattr(layer, 'Path'):
                    path = layer.Path.decode() if isinstance(layer.Path, bytes) else str(layer.Path)
                    http_info['路径'] = path
                    
                if hasattr(layer, 'Http_Version'):
                    version = layer.Http_Version.decode() if isinstance(layer.Http_Version, bytes) else str(layer.Http_Version)
                    http_info['版本'] = version
                
                # 解析头部字段
                if hasattr(layer, 'Host'):
                    host = layer.Host.decode() if isinstance(layer.Host, bytes) else str(layer.Host)
                    http_info['主机'] = host
                    
                if hasattr(layer, 'User_Agent'):
                    ua = layer.User_Agent.decode() if isinstance(layer.User_Agent, bytes) else str(layer.User_Agent)
                    http_info['用户代理'] = ua
                    
            elif hasattr(layer, 'Status_Code'):
                # HTTP响应
                http_info['类型'] = 'HTTP响应'
                status = layer.Status_Code.decode() if isinstance(layer.Status_Code, bytes) else str(layer.Status_Code)
                http_info['状态码'] = status
                
                if hasattr(layer, 'Reason_Phrase'):
                    reason = layer.Reason_Phrase.decode() if isinstance(layer.Reason_Phrase, bytes) else str(layer.Reason_Phrase)
                    http_info['原因短语'] = reason
        except Exception:
            pass
            
        return http_info
        
    def _update_main_info(self, packet_info, layer_name, layer_info):
        """更新数据包主要信息"""
        if layer_name == 'IP':
            packet_info['src_ip'] = layer_info.get('源IP地址', '')
            packet_info['dst_ip'] = layer_info.get('目的IP地址', '')
            packet_info['protocol'] = 'IP'
            
        elif layer_name == 'IPv6':
            packet_info['src_ip'] = layer_info.get('源IPv6地址', '')
            packet_info['dst_ip'] = layer_info.get('目的IPv6地址', '')
            packet_info['protocol'] = 'IPv6'
            
        elif layer_name == 'TCP':
            packet_info['src_port'] = layer_info.get('源端口', '')
            packet_info['dst_port'] = layer_info.get('目的端口', '')
            packet_info['protocol'] = 'TCP'
            
        elif layer_name == 'UDP':
            packet_info['src_port'] = layer_info.get('源端口', '')
            packet_info['dst_port'] = layer_info.get('目的端口', '')
            packet_info['protocol'] = 'UDP'
            
        elif layer_name == 'ICMP':
            packet_info['protocol'] = 'ICMP'
            
        elif layer_name == 'ARP':
            packet_info['src_ip'] = layer_info.get('发送方IP', '')
            packet_info['dst_ip'] = layer_info.get('目标IP', '')
            packet_info['protocol'] = 'ARP'
            
        elif layer_name == 'DNS':
            packet_info['protocol'] = 'DNS'
            
        elif layer_name == 'HTTP':
            packet_info['protocol'] = 'HTTP'
            
    def _generate_summary_info(self, packet_info):
        """生成简要信息"""
        protocol = packet_info['protocol']
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        src_port = packet_info['src_port']
        dst_port = packet_info['dst_port']
        
        if protocol in ['TCP', 'UDP']:
            if src_port and dst_port:
                packet_info['info'] = f"{src_port} → {dst_port}"
            else:
                packet_info['info'] = f"{src_ip} → {dst_ip}"
                
        elif protocol == 'ICMP':
            icmp_layer = packet_info['layers'].get('02_ICMP', {})
            icmp_type = icmp_layer.get('类型', '')
            packet_info['info'] = icmp_type
            
        elif protocol == 'ARP':
            arp_layer = packet_info['layers'].get('01_ARP', {})
            op_code = arp_layer.get('操作码', '')
            packet_info['info'] = op_code
            
        elif protocol == 'DNS':
            dns_layer = packet_info['layers'].get('03_DNS', {})
            query = dns_layer.get('查询', '')
            packet_info['info'] = query
            
        elif protocol == 'HTTP':
            http_layer = next((layer for layer_name, layer in packet_info['layers'].items() 
                             if 'HTTP' in layer_name), {})
            if http_layer.get('类型') == 'HTTP请求':
                method = http_layer.get('方法', '')
                path = http_layer.get('路径', '')
                packet_info['info'] = f"{method} {path}"
            elif http_layer.get('类型') == 'HTTP响应':
                status = http_layer.get('状态码', '')
                reason = http_layer.get('原因短语', '')
                packet_info['info'] = f"{status} {reason}"
                
        else:
            packet_info['info'] = f"{src_ip} → {dst_ip}" if src_ip and dst_ip else "Unknown"
