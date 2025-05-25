import sys
import os
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ui import MainWindow


def check_dependencies():
    """检查必要的依赖"""
    missing_deps = []
    
    try:
        import scapy
    except ImportError:
        missing_deps.append("scapy")
        
    try:
        import matplotlib
    except ImportError:
        missing_deps.append("matplotlib")
        
    try:
        import psutil
    except ImportError:
        missing_deps.append("psutil")
        
    return missing_deps


def main():
    """主函数"""
    # 创建应用程序
    app = QApplication(sys.argv)
    app.setApplicationName("网络协议嗅探器")
    app.setApplicationVersion("1.0.0")
    
    # 设置应用程序属性
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    # 检查依赖
    missing_deps = check_dependencies()
    if missing_deps:
        QMessageBox.critical(
            None, 
            "缺少依赖", 
            f"缺少以下依赖包：{', '.join(missing_deps)}\n\n"
            f"请运行以下命令安装：\n"
            f"pip install {' '.join(missing_deps)}"
        )
        return 1
    
    try:
        # 创建主窗口
        main_window = MainWindow()
        main_window.show()
        
        # 运行应用程序
        return app.exec_()
        
    except Exception as e:
        QMessageBox.critical(
            None, 
            "启动错误", 
            f"应用程序启动失败：\n{str(e)}"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())