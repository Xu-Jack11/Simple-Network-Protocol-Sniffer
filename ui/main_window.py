import sys
import os
import threading
import time
from datetime import datetime
from collections import defaultdict

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QMenuBar, QToolBar, QTreeWidget, QTreeWidgetItem,
                           QPlainTextEdit, QSplitter, QLabel, QComboBox, QPushButton,
                           QLineEdit, QGroupBox, QTabWidget, QTableWidget,
                           QTableWidgetItem, QHeaderView, QMessageBox,
                           QProgressBar, QStatusBar, QAction, QToolTip)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QIcon, QFont, QColor

import matplotlib.pyplot as plt
import math
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import psutil
from scapy.all import sniff

# 设置matplotlib的中文字体支持
plt.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from .packet_sniffer import PacketSniffer
from .packet_analyzer import PacketAnalyzer
from config import UI_CONFIG, PROTOCOL_COLORS, STYLESHEET
from utils import PacketStatistics, FilterParser


class PacketSnifferThread(QThread):
    """数据包捕获线程"""
    packet_captured = pyqtSignal(object)
    
    def __init__(self, interface, filter_condition=""):
        super().__init__()
        self.interface = interface
        self.filter_condition = filter_condition
        self.sniffer = PacketSniffer()
        self.running = False
        
    def run(self):
        """启动数据包捕获"""
        self.running = True
        self.sniffer.start_capture(
            interface=self.interface,
            filter_condition=self.filter_condition,
            packet_callback=self.packet_captured.emit
        )
        
    def stop(self):
        """停止数据包捕获"""
        self.running = False
        self.sniffer.stop_capture()
        self.quit()


class StatisticsCanvas(FigureCanvas):
    """协议统计图表画布"""
    
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(self.fig)
        self.setParent(parent)
        
        # 创建子图
        self.protocol_ax = self.fig.add_subplot(211)
        self.traffic_ax = self.fig.add_subplot(212)
        # 绑定鼠标悬停事件，用于显示包数提示
        self.mpl_connect('motion_notify_event', self.on_hover)
        
        self.protocol_data = defaultdict(int)
        self.traffic_data = []
        self.time_labels = []
        # 用于计算每秒包数的前一次累计值
        self.prev_count = 0
        
    def update_protocol_stats(self, protocol_counts):
        """更新协议统计图"""
        self.protocol_ax.clear()
        if protocol_counts:
            protocols = list(protocol_counts.keys())
            counts = list(protocol_counts.values())
            total = sum(counts)
            # 只有占比>=5%时才显示标签
            labels = [f if (counts[i] / total * 100) >= 5 else '' for i, f in enumerate(protocols)]
            # 使用配置中的协议颜色映射
            colors = [PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS.get('Unknown', '#CCCCCC')) for proto in protocols]
            # 扇区文本全部放置在外部，并使用引导线
            wedges, texts = self.protocol_ax.pie(
                counts, labels=labels, autopct=None,
                colors=colors, startangle=90,
                labeldistance=1.1, pctdistance=0.8,
                wedgeprops={'linewidth': 1, 'edgecolor': 'white'}
            )
            # 自动添加百分比文本在外部
            for i, wedge in enumerate(wedges):
                pct = counts[i] / total * 100
                if pct < 5:
                    continue
                angle = (wedge.theta2 + wedge.theta1) / 2
                x = math.cos(math.radians(angle)) * 1.2
                y = math.sin(math.radians(angle)) * 1.2
                self.protocol_ax.text(x, y, f"{counts[i]} ({pct:.1f}%)",
                                     ha='center', va='center', fontsize=10)
            self.protocol_ax.set_title('协议分布统计', fontsize=12, fontweight='bold')
            # 保存扇区和数据用于悬停
            self._wedges = wedges
            self._protocols = protocols
            self._counts = counts
            
        self.draw()
        
    def update_traffic_stats(self, packet_count):
        """更新流量趋势图"""
        current_time = datetime.now().strftime('%H:%M:%S')
        # 计算每秒包数，并更新prev_count
        # UI_CONFIG['update_interval'] 为毫秒
        interval_sec = UI_CONFIG.get('update_interval', 2000) / 1000.0
        diff = packet_count - self.prev_count
        per_sec = diff / interval_sec if interval_sec > 0 else 0
        self.prev_count = packet_count
        self.traffic_data.append(per_sec)
        self.time_labels.append(current_time)
        
        # 只保留最近30个数据点
        if len(self.traffic_data) > 30:
            self.traffic_data.pop(0)
            self.time_labels.pop(0)
            
        self.traffic_ax.clear()
        self.traffic_ax.plot(range(len(self.traffic_data)), self.traffic_data,
                             color=PROTOCOL_COLORS.get('Unknown', '#45B7D1'), linewidth=2,
                             marker='o', markersize=4)
        self.traffic_ax.set_title('数据包传输趋势', fontsize=12, fontweight='bold')
        self.traffic_ax.set_xlabel('时间')
        self.traffic_ax.set_ylabel('每秒包数')
        self.traffic_ax.grid(True, alpha=0.3)
        
        # 设置x轴标签
        if len(self.time_labels) > 1:
            step = max(1, len(self.time_labels) // 5)
            self.traffic_ax.set_xticks(range(0, len(self.time_labels), step))
            self.traffic_ax.set_xticklabels([self.time_labels[i] for i in range(0, len(self.time_labels), step)], 
                                          rotation=45, fontsize=8)
        
        self.draw()
    
    def on_hover(self, event):
        """鼠标悬停时在对应扇区显示包数提示"""
        if event.inaxes != self.protocol_ax:
            QToolTip.hideText()
            return
        for wedge, proto, cnt in zip(getattr(self, '_wedges', []), getattr(self, '_protocols', []), getattr(self, '_counts', [])):
            contains, _ = wedge.contains(event)
            if contains:
                # 使用全局坐标显示工具提示
                try:
                    pos = event.guiEvent.globalPos()
                except:
                    pos = None
                QToolTip.showText(pos, f"{proto}: {cnt} 个包")
                return
        QToolTip.hideText()


class MainWindow(QMainWindow):
    """主窗口类"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("网络协议嗅探器")
        self.setGeometry(100, 100, UI_CONFIG['window_width'], UI_CONFIG['window_height'])
        
        # 设置应用程序字体
        font = QFont("Microsoft YaHei UI", 9)
        if not font.exactMatch():
            font = QFont("Microsoft YaHei", 9)
        if not font.exactMatch():
            font = QFont("SimSun", 9)
        self.setFont(font)
        
        # 初始化变量
        self.sniffer_thread = None
        self.packet_analyzer = PacketAnalyzer()
        self.captured_packets = []
        self.protocol_counts = defaultdict(int)
        self.packet_count = 0
        self.packet_statistics = PacketStatistics()
        self.filter_parser = FilterParser()
        # 当前基于内容的协议过滤器，如HTTP、DNS等
        self.current_protocol_filter = None
        
        # 设置样式
        self.setStyleSheet(STYLESHEET)
        
        self.init_ui()
        self.init_menu_and_toolbar()
        self.setup_timer()
        
    def init_ui(self):
        """初始化用户界面"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 控制面板
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)
        
        # 主分割器
        main_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧面板（数据包列表和详细信息）
        left_panel = self.create_left_panel()
        main_splitter.addWidget(left_panel)
        
        # 右侧面板（统计图表）
        right_panel = self.create_right_panel()
        main_splitter.addWidget(right_panel)
        
        # 设置分割器比例
        main_splitter.setSizes([800, 600])
        main_layout.addWidget(main_splitter)
        
        # 状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("就绪")
        
    def create_control_panel(self):
        """创建控制面板"""
        control_group = QGroupBox("控制面板")
        layout = QHBoxLayout(control_group)
        
        # 网络接口选择
        layout.addWidget(QLabel("网络接口:"))
        self.interface_combo = QComboBox()
        self.load_network_interfaces()
        layout.addWidget(self.interface_combo)
        
        # 过滤条件
        layout.addWidget(QLabel("过滤条件:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("例如: tcp port 80")
        layout.addWidget(self.filter_input)
        
        # 控制按钮
        self.start_button = QPushButton("开始捕获")
        self.start_button.clicked.connect(self.start_capture)
        layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("停止捕获")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton("清空列表")
        self.clear_button.clicked.connect(self.clear_packets)
        layout.addWidget(self.clear_button)
        
        layout.addStretch()
        
        # 统计标签
        self.packet_count_label = QLabel("数据包总数: 0")
        layout.addWidget(self.packet_count_label)
        
        return control_group
        
    def create_left_panel(self):
        """创建左侧面板"""
        left_widget = QWidget()
        layout = QVBoxLayout(left_widget)
        
        # 数据包列表
        packet_group = QGroupBox("数据包列表")
        packet_layout = QVBoxLayout(packet_group)
        
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels([
            "序号", "时间", "源IP", "目的IP", "协议", "长度", "信息"
        ])
        
        # 设置表格样式
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        # 设置表格为只读模式，不可编辑
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.itemSelectionChanged.connect(self.on_packet_selected)
        
        packet_layout.addWidget(self.packet_table)
        layout.addWidget(packet_group)
        
        # 详细信息展示
        detail_group = QGroupBox("详细信息")
        detail_layout = QVBoxLayout(detail_group)
        
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabel("协议层次结构")
        detail_layout.addWidget(self.detail_tree)
        
        layout.addWidget(detail_group)
        # 添加原始数据展示区域
        raw_group = QGroupBox("原始数据")
        raw_layout = QVBoxLayout(raw_group)
        # 使用 QPlainTextEdit 保持等宽列对齐
        self.raw_text = QPlainTextEdit()
        self.raw_text.setReadOnly(True)
        # 指定等宽字体，优先 Consolas，回退 Courier New
        from PyQt5.QtGui import QFont
        mono_font = QFont("Consolas", 8)
        if not mono_font.exactMatch():
            mono_font = QFont("Courier New", 8)
        self.raw_text.setFont(mono_font)
        # 禁用自动换行以保持列对齐
        self.raw_text.setLineWrapMode(QPlainTextEdit.NoWrap)
        raw_layout.addWidget(self.raw_text)
        layout.addWidget(raw_group)
        
        # 设置垂直分割比例
        left_widget.setMinimumWidth(600)
        
        return left_widget
        
    def create_right_panel(self):
        """创建右侧面板"""
        right_widget = QWidget()
        layout = QVBoxLayout(right_widget)
        
        # 统计图表
        stats_group = QGroupBox("协议统计")
        stats_layout = QVBoxLayout(stats_group)
        
        # 改为将主窗口作为父对象，以便工具提示定位
        self.stats_canvas = StatisticsCanvas(self, width=5, height=6, dpi=100)
        stats_layout.addWidget(self.stats_canvas)
        
        layout.addWidget(stats_group)
        right_widget.setMinimumWidth(400)
        return right_widget
        
    def init_menu_and_toolbar(self):
        """初始化菜单栏和工具栏"""
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu('文件')
        
        save_action = QAction('保存数据包', self)
        save_action.setShortcut('Ctrl+S')
        save_action.triggered.connect(self.save_packets)
        file_menu.addAction(save_action)
        
        load_action = QAction('加载数据包', self)
        load_action.setShortcut('Ctrl+O')
        load_action.triggered.connect(self.load_packets)
        file_menu.addAction(load_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('退出', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 捕获菜单
        capture_menu = menubar.addMenu('捕获')
        
        start_action = QAction('开始捕获', self)
        start_action.setShortcut('F5')
        start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(start_action)
        
        stop_action = QAction('停止捕获', self)
        stop_action.setShortcut('F6')
        stop_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(stop_action)
        
        # 视图菜单
        view_menu = menubar.addMenu('视图')
        
        clear_action = QAction('清空列表', self)
        clear_action.setShortcut('Ctrl+L')
        clear_action.triggered.connect(self.clear_packets)
        view_menu.addAction(clear_action)
        
        # 帮助菜单
        help_menu = menubar.addMenu('帮助')
        
        about_action = QAction('关于', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        # 工具栏
        toolbar = QToolBar()
        toolbar.addAction(start_action)
        toolbar.addAction(stop_action)
        toolbar.addSeparator()
        toolbar.addAction(clear_action)
        toolbar.addSeparator()
        toolbar.addAction(save_action)
        self.addToolBar(toolbar)
        
    def load_network_interfaces(self):
        """加载网络接口"""
        try:
            interfaces = psutil.net_if_addrs()
            for interface_name in interfaces.keys():
                self.interface_combo.addItem(interface_name)
        except Exception as e:
            QMessageBox.warning(self, "警告", f"获取网络接口失败: {str(e)}")
            
    def setup_timer(self):
        """设置定时器用于更新统计图表"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_statistics)
        self.update_timer.start(2000)  # 每2秒更新一次
        
    def start_capture(self):
        """开始数据包捕获"""
        interface = self.interface_combo.currentText()
        filter_condition = self.filter_input.text().strip()
        
        # 支持简写协议过滤，将常见协议映射为合法的 BPF 表达式
        protocol_filter_map = {
            'http': 'tcp port 80',
            'https': 'tcp port 443',
            'dns': 'port 53',
            'ftp': 'tcp port 21',
            'ssh': 'tcp port 22'
        }
        lower_filter = filter_condition.lower()
        if lower_filter in protocol_filter_map:
            # 标记基于内容的协议过滤器，BPF仅按端口过滤
            self.current_protocol_filter = lower_filter.upper()
            filter_condition = protocol_filter_map[lower_filter]
        else:
            self.current_protocol_filter = None
        
        if not interface:
            QMessageBox.warning(self, "警告", "请选择网络接口")
            return
        
        # 验证过滤表达式语法
        if filter_condition:
            try:
                sniff(iface=interface, filter=filter_condition, count=0, timeout=0.1)
            except Exception as e:
                QMessageBox.warning(self, "过滤错误", f"无效过滤表达式: {str(e)}")
                return
        try:
            self.sniffer_thread = PacketSnifferThread(interface, filter_condition)
            self.sniffer_thread.packet_captured.connect(self.on_packet_captured)
            self.sniffer_thread.start()
            # 重新启动图表更新定时器
            self.update_timer.start(2000)

            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_bar.showMessage(f"正在捕获数据包 - 接口: {interface}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"启动捕获失败: {str(e)}")
            
    def stop_capture(self):
        """停止数据包捕获"""
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.sniffer_thread = None
        
        # 停止图表更新定时器
        self.update_timer.stop()
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("捕获已停止")
        
    def clear_packets(self):
        """清空数据包列表"""
        self.captured_packets.clear()
        self.protocol_counts.clear()
        self.packet_count = 0
        self.packet_table.setRowCount(0)
        self.detail_tree.clear()
        self.packet_count_label.setText("数据包总数: 0")
        # 清空统计图表
        self.stats_canvas.protocol_ax.clear()
        self.stats_canvas.traffic_ax.clear()
        self.stats_canvas.traffic_data.clear()
        self.stats_canvas.time_labels.clear()
        self.stats_canvas.draw()
        
    def on_packet_captured(self, packet):
        """处理捕获的数据包"""
        try:
            # 分析数据包并根据内容协议进行辅助过滤
            packet_info = self.packet_analyzer.analyze_packet(packet)
            # 若设定了基于内容的协议过滤，如HTTP，则丢弃非匹配包
            if self.current_protocol_filter and packet_info.get('protocol') != self.current_protocol_filter:
                return
            self.captured_packets.append(packet_info)
            self.packet_count += 1
            
            # 更新协议统计
            protocol = packet_info.get('protocol', 'Unknown')
            self.protocol_counts[protocol] += 1
            
            # 添加到表格
            self.add_packet_to_table(packet_info)
            
            # 更新计数
            self.packet_count_label.setText(f"数据包总数: {self.packet_count}")
        except Exception as e:
            print(f"处理数据包时出错: {str(e)}")
            
    def add_packet_to_table(self, packet_info):
        """将数据包添加到表格中"""
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        # 设置表格项
        items = [
            str(self.packet_count),
            packet_info.get('timestamp', ''),
            packet_info.get('src_ip', ''),
            packet_info.get('dst_ip', ''),
            packet_info.get('protocol', ''),
            str(packet_info.get('length', 0)),
            packet_info.get('info', '')
        ]
        
        for col, item in enumerate(items):
            table_item = QTableWidgetItem(item)
            self.packet_table.setItem(row, col, table_item)
        
        # 根据协议类型设置行背景颜色
        protocol = packet_info.get('protocol', 'Unknown')
        color = PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS.get('Unknown', '#FFFFFF'))
        for col_index in range(self.packet_table.columnCount()):
            self.packet_table.item(row, col_index).setBackground(QColor(color))
        # 自动滚动到最新项
        self.packet_table.scrollToBottom()
        
    def on_packet_selected(self):
        """处理数据包选择事件"""
        current_row = self.packet_table.currentRow()
        if current_row >= 0 and current_row < len(self.captured_packets):
            packet_info = self.captured_packets[current_row]
            self.display_packet_details(packet_info)
            
    def display_packet_details(self, packet_info):
        """显示数据包详细信息"""
        self.detail_tree.clear()
        
        # 创建协议层次结构
        for layer_name, layer_info in packet_info.get('layers', {}).items():
            layer_item = QTreeWidgetItem(self.detail_tree, [layer_name])
            layer_item.setExpanded(True)
            
            for field_name, field_value in layer_info.items():
                field_item = QTreeWidgetItem(layer_item, [f"{field_name}: {field_value}"])
                
        self.detail_tree.expandAll()
        
        # 显示原始数据
        raw_data = packet_info.get('raw_data', '')
        # 格式化原始字节为十六进制和 ASCII 对照显示，每行16字节
        raw_bytes = packet_info.get('raw_bytes', b'')
        lines = []
        bytes_per_line = 16
        for i in range(0, len(raw_bytes), bytes_per_line):
            chunk = raw_bytes[i:i+bytes_per_line]
            # 固定字节宽度，对短行使用空格占位
            hex_vals = [f"{b:02x}" for b in chunk] + ['  '] * (bytes_per_line - len(chunk))
            hex_part = ' '.join(hex_vals)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{i:04x}  {hex_part}  {ascii_part}")
        formatted = '\n'.join(lines)
        self.raw_text.setPlainText(formatted)
        
    def update_statistics(self):
        """更新统计图表"""
        if self.protocol_counts:
            self.stats_canvas.update_protocol_stats(dict(self.protocol_counts))
            self.stats_canvas.update_traffic_stats(self.packet_count)
    
    def save_packets(self):
        """保存数据包到文件"""
        from PyQt5.QtWidgets import QFileDialog
        import json
        
        if not self.captured_packets:
            QMessageBox.information(self, "提示", "没有数据包可保存")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存数据包", "", "JSON文件 (*.json);;所有文件 (*)")
        
        if file_path:
            try:
                # 准备保存的数据
                save_data = {
                    'total_packets': self.packet_count,
                    'capture_time': datetime.now().isoformat(),
                    'packets': []
                }
                
                for packet_info in self.captured_packets:
                    # 移除不能序列化的原始数据包对象
                    packet_copy = packet_info.copy()
                    if 'raw_packet' in packet_copy:
                        del packet_copy['raw_packet']
                    save_data['packets'].append(packet_copy)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(save_data, f, ensure_ascii=False, indent=2)
                
                QMessageBox.information(self, "成功", f"数据包已保存到: {file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存失败: {str(e)}")
    
    def load_packets(self):
        """从文件加载数据包"""
        from PyQt5.QtWidgets import QFileDialog
        import json
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "加载数据包", "", "JSON文件 (*.json);;所有文件 (*)")
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 清空当前数据
                self.clear_packets()
                
                # 加载数据包
                packets = data.get('packets', [])
                for packet_info in packets:
                    self.captured_packets.append(packet_info)
                    self.packet_count += 1
                    
                    # 更新协议统计
                    protocol = packet_info.get('protocol', 'Unknown')
                    self.protocol_counts[protocol] += 1
                    
                    # 添加到表格
                    self.add_packet_to_table(packet_info)
                
                # 更新计数
                self.packet_count_label.setText(f"数据包总数: {self.packet_count}")
                
                QMessageBox.information(self, "成功", f"已加载 {len(packets)} 个数据包")
                
            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载失败: {str(e)}")
    
    def show_about(self):
        """显示关于对话框"""
        from config import APP_CONFIG
        
        about_text = f"""
        <h3>{APP_CONFIG['name']}</h3>
        <p>版本: {APP_CONFIG['version']}</p>
        <p>作者: {APP_CONFIG['author']}</p>
        <p>{APP_CONFIG['description']}</p>
        <p>基于 PyQt5 和 Scapy 构建</p>
        <hr>
        <p>主要功能:</p>
        <ul>
        <li>实时捕获网络数据包</li>
        <li>支持多种协议解析</li>
        <li>直观的统计图表展示</li>
        <li>详细的协议分析</li>
        </ul>
        """
        
        QMessageBox.about(self, "关于", about_text)
            
    def closeEvent(self, event):
        """窗口关闭事件"""
        if self.sniffer_thread:
            self.stop_capture()
        event.accept()
