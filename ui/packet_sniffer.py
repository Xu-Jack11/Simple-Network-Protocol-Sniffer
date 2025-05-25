import threading
import time
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTP


class PacketSniffer:
    """网络数据包嗅探器"""
    
    def __init__(self):
        self.capture_thread = None
        self.stop_sniffing = False
        self.packet_callback = None
        
    def get_available_interfaces(self):
        """获取可用的网络接口"""
        try:
            return get_if_list()
        except Exception as e:
            print(f"获取网络接口失败: {str(e)}")
            return []
            
    def start_capture(self, interface, filter_condition="", packet_callback=None):
        """开始捕获数据包"""
        self.stop_sniffing = False
        self.packet_callback = packet_callback
        
        # 创建捕获线程
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, filter_condition)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def stop_capture(self):
        """停止捕获数据包"""
        self.stop_sniffing = True
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
            
    def _capture_packets(self, interface, filter_condition):
        """捕获数据包的内部方法"""
        try:
            # 使用scapy进行数据包捕获
            sniff(
                iface=interface,
                filter=filter_condition if filter_condition else None,
                prn=self._process_packet,
                stop_filter=lambda x: self.stop_sniffing,
                store=False
            )
        except Exception as e:
            print(f"数据包捕获错误: {str(e)}")
            
    def _process_packet(self, packet):
        """处理捕获到的数据包"""
        if self.packet_callback and not self.stop_sniffing:
            self.packet_callback(packet)
            
    def parse_packet_basic_info(self, packet):
        """解析数据包基本信息"""
        packet_info = {
            'timestamp': time.strftime('%H:%M:%S', time.localtime()),
            'length': len(packet),
            'src_ip': '',
            'dst_ip': '',
            'protocol': '',
            'info': ''
        }
        
        # 解析以太网层
        if packet.haslayer(Ether):
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
            
        # 解析IP层
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['protocol'] = ip_layer.proto
            packet_info['ttl'] = ip_layer.ttl
            packet_info['ip_len'] = ip_layer.len
            
            # 判断具体协议
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['info'] = f"{tcp_layer.sport} → {tcp_layer.dport}"
                
                # 检查HTTP
                if packet.haslayer(HTTP):
                    packet_info['protocol'] = 'HTTP'
                    
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
                packet_info['info'] = f"{udp_layer.sport} → {udp_layer.dport}"
                
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = f"Type: {icmp_layer.type}, Code: {icmp_layer.code}"
                
        return packet_info


# class TSharkSniffer:
#     """使用TShark进行数据包捕获的替代方案"""
    
#     def __init__(self):
#         self.process = None
#         self.capture_thread = None
#         self.stop_sniffing = False
        
#     def start_capture_with_tshark(self, interface, filter_condition="", packet_callback=None):
#         """使用TShark开始捕获"""
#         import subprocess
#         import json
        
#         self.stop_sniffing = False
        
#         # 构建tshark命令
#         cmd = [
#             'tshark',
#             '-i', interface,
#             '-T', 'json',
#             '-l'  # 立即刷新输出
#         ]
        
#         if filter_condition:
#             cmd.extend(['-f', filter_condition])
            
#         try:
#             self.process = subprocess.Popen(
#                 cmd,
#                 stdout=subprocess.PIPE,
#                 stderr=subprocess.PIPE,
#                 text=True,
#                 bufsize=1
#             )
            
#             # 创建读取线程
#             self.capture_thread = threading.Thread(
#                 target=self._read_tshark_output,
#                 args=(packet_callback,)
#             )
#             self.capture_thread.daemon = True
#             self.capture_thread.start()
            
#         except FileNotFoundError:
#             raise Exception("TShark未找到，请确保已安装Wireshark")
#         except Exception as e:
#             raise Exception(f"启动TShark失败: {str(e)}")
            
#     def _read_tshark_output(self, packet_callback):
#         """读取TShark输出"""
#         import json
        
#         buffer = ""
        
#         while not self.stop_sniffing and self.process and self.process.poll() is None:
#             try:
#                 line = self.process.stdout.readline()
#                 if not line:
#                     break
                    
#                 buffer += line
                
#                 # 尝试解析JSON
#                 try:
#                     if buffer.strip().endswith('}'):
#                         packet_data = json.loads(buffer.strip())
#                         if packet_callback:
#                             packet_callback(packet_data)
#                         buffer = ""
#                 except json.JSONDecodeError:
#                     # 继续累积数据
#                     continue
                    
#             except Exception as e:
#                 print(f"读取TShark输出时出错: {str(e)}")
#                 break
                
#     def stop_capture(self):
#         """停止TShark捕获"""
#         self.stop_sniffing = True
        
#         if self.process:
#             self.process.terminate()
#             try:
#                 self.process.wait(timeout=5)
#             except:
#                 self.process.kill()
#             self.process = None
            
#         if self.capture_thread and self.capture_thread.is_alive():
#             self.capture_thread.join(timeout=2)
