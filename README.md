# 网络协议嗅探器

一个基于Python、PyQt5和Scapy构建的网络协议嗅探器，用于实时捕获、分析和展示网络数据包。

## 功能特点

### 🔍 数据包捕获
- 实时捕获网络数据包
- 支持选择网络接口
- 自定义过滤条件（按IP、端口、协议等）

### 📊 协议解析
- **网络层**: IP、IPv6、ARP、ICMP
- **传输层**: TCP、UDP
- **应用层**: HTTP、DNS
- 详细的协议字段解析
- 层次化的协议栈展示

### 🎨 直观界面
- 现代化的PyQt5 GUI界面
- 数据包列表实时更新
- 详细信息树形展示
- 协议统计饼图
- 流量趋势折线图

### 📈 统计分析
- 协议分布统计
- 数据包传输趋势
- IP地址访问统计
- 端口使用统计
- 实时流量监控

### 💾 数据管理
- 保存捕获的数据包到JSON文件
- 加载历史数据包进行分析
- 导出统计报告

## 系统要求

### 操作系统
- Windows 10/11 (推荐)

### Python版本
- Python 3.7+

### 依赖包
- PyQt5 >= 5.15.0
- scapy >= 2.4.5
- matplotlib >= 3.5.0
- psutil >= 5.8.0

### 网络驱动 (Windows)
- WinPcap 或 Npcap (推荐Npcap)
- 下载地址: https://nmap.org/npcap/

## 安装指南
### 方案一
#### 下载Release中打包好的可执行程序并运行
- 前往 [Releases 页面](https://github.com/Xu-Jack11/Simple-Network-Protocol-Sniffer/releases) 下载最新版本的可执行程序
- 解压后直接运行，无需安装Python环境
### 方案二
#### 1. 安装依赖
```bash
pip install -r requirements.txt
```

#### 2. Windows安装驱动
- 下载并安装Npcap: https://nmap.org/npcap/
- 安装时勾选"WinPcap API compatibility"选项

#### 3. 运行程序

```bash
python main.py
```

## 使用指南

### 基本操作

1. **选择网络接口**
   - 在界面顶部的下拉菜单中选择要监听的网络接口

2. **设置过滤条件**
   - 在过滤输入框中输入BPF格式的过滤条件
   - 例如：`tcp port 80`, `host 192.168.1.1`

3. **开始捕获**
   - 点击"开始捕获"按钮或按F5键

4. **查看详细信息**
   - 点击数据包列表中的任意一行

5. **停止捕获**
   - 点击"停止捕获"按钮或按F6键

### 快捷键
- `F5` - 开始捕获
- `F6` - 停止捕获
- `Ctrl+S` - 保存数据包
- `Ctrl+O` - 加载数据包
- `Ctrl+L` - 清空列表
- `Ctrl+Q` - 退出程序

## 项目结构

```
Simple Network Protocol Sniffer/
├── main.py                 # 主程序入口
├── run.py                  # 启动脚本
├── config.py              # 配置文件
├── utils.py               # 工具函数
├── requirements.txt       # Python依赖
├── README.md             # 说明文档
└── ui/                   # 用户界面模块
    ├── __init__.py
    ├── main_window.py    # 主窗口
    ├── packet_sniffer.py # 数据包捕获
    └── packet_analyzer.py # 数据包分析
```

## 常见问题

### Q: Windows上提示"找不到WinPcap"怎么办？
A: 请下载并安装Npcap驱动程序：https://nmap.org/npcap/

### Q: 程序需要管理员权限吗？
A: 建议以管理员身份运行，这样可以访问所有网络接口。

### Q: 支持哪些协议？
A: 目前支持IP、IPv6、TCP、UDP、ICMP、ARP、HTTP、DNS等常见协议。

## 许可证

本项目采用MIT许可证。