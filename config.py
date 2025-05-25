"""
配置文件
"""

# 应用程序设置
APP_CONFIG = {
    'name': '网络协议嗅探器',
    'version': '1.0.0',
    'author': 'Xu-Jack11',
    'description': '一个用于捕获和分析网络数据包的工具'
}

# 界面设置
UI_CONFIG = {
    'window_width': 1400,
    'window_height': 900,
    'update_interval': 2000,  # 统计图表更新间隔（毫秒）
    'max_packets_display': 10000,  # 最大显示数据包数量
    'traffic_history_points': 30  # 流量趋势图历史点数
}

# 数据包捕获设置
CAPTURE_CONFIG = {
    'default_filter': '',
    'packet_timeout': 1,  # 数据包超时时间（秒）
    'buffer_size': 65536,  # 缓冲区大小
    'max_packet_size': 65535  # 最大数据包大小
}

# 协议颜色配置
PROTOCOL_COLORS = {
    'TCP': '#FF6B6B',
    'UDP': '#4ECDC4', 
    'ICMP': '#45B7D1',
    'HTTP': '#96CEB4',
    'HTTPS': '#FECA57',
    'DNS': '#FF9FF3',
    'ARP': '#54A0FF',
    'IPv6': '#5F27CD',
    'Unknown': '#CCCCCC'
}

# 样式表配置
STYLESHEET = """
    * {
        font-family: "Microsoft YaHei UI", "Microsoft YaHei", "SimSun", Arial, sans-serif;
        font-size: 9pt;
    }
    QMainWindow {
        background-color: #f0f0f0;
    }
    QGroupBox {
        font-weight: bold;
        border: 2px solid #cccccc;
        border-radius: 5px;
        margin-top: 10px;
        padding-top: 10px;
        background-color: white;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 5px 0 5px;
        color: #333333;
    }
    QPushButton {
        background-color: #4CAF50;
        border: none;
        color: white;
        padding: 8px 16px;
        font-size: 14px;
        border-radius: 4px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #45a049;
    }
    QPushButton:pressed {
        background-color: #3d8b40;
    }
    QPushButton:disabled {
        background-color: #cccccc;
        color: #666666;
    }
    QTableWidget {
        gridline-color: #d0d0d0;
        background-color: white;
        alternate-background-color: #f8f8f8;
        selection-background-color: #3498db;
    }
    QTableWidget::item {
        padding: 5px;
    }
    QTreeWidget {
        background-color: white;
        border: 1px solid #d0d0d0;
        border-radius: 3px;
    }
    QTreeWidget::item {
        padding: 3px;
    }
    QTreeWidget::item:selected {
        background-color: #3498db;
        color: white;
    }
    QComboBox {
        padding: 5px;
        border: 1px solid #cccccc;
        border-radius: 3px;
        background-color: white;
    }
    QLineEdit {
        padding: 5px;
        border: 1px solid #cccccc;
        border-radius: 3px;
        background-color: white;
    }
    QStatusBar {
        background-color: #ecf0f1;
        border-top: 1px solid #bdc3c7;
    }
"""
