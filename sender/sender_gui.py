import sys
import os
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QFileDialog, QLineEdit,
    QLabel, QSpinBox, QCheckBox, QGroupBox, QComboBox, QMessageBox,
    QProgressBar, QTextEdit, QHeaderView, QInputDialog
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont

from sender.ip_manager import IPManager
from sender.interface_manager import InterfaceManager
from sender.traffic_sender import TrafficSender
from common.config import SenderConfig, IPConfig

class TrafficSenderThread(QThread):
    """流量发送线程"""
    status_update = Signal(dict)
    finished = Signal()
    
    def __init__(self, traffic_sender, ip_list):
        super().__init__()
        self.traffic_sender = traffic_sender
        self.ip_list = ip_list
    
    def run(self):
        """线程运行函数"""
        self.traffic_sender.start_sending(self.ip_list)
        self.finished.emit()
    
    def stop(self):
        """停止发送"""
        self.traffic_sender.stop_sending()

class SenderGUI(QMainWindow):
    """发送端主界面"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("网络流量生成工具 - 发送端")
        self.setGeometry(100, 100, 1000, 700)
        
        # 初始化管理器
        self.ip_manager = IPManager()
        self.interface_manager = InterfaceManager()
        self.sender_config = SenderConfig()
        self.traffic_sender = TrafficSender(self.sender_config)
        
        # 发送线程
        self.send_thread = None
        
        # 创建主布局
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # 创建标签页
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # 创建各个标签页
        self.create_ip_list_tab()
        self.create_interface_tab()
        self.create_traffic_config_tab()
        self.create_status_tab()
        
        # 创建底部状态栏
        self.statusBar().showMessage("就绪")
        
        # 创建定时器用于更新状态
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)  # 每秒更新一次
    
    def create_ip_list_tab(self):
        """创建IP列表管理标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 顶部按钮布局
        button_layout = QHBoxLayout()
        
        # 导入按钮
        self.import_btn = QPushButton("导入IP列表")
        self.import_btn.clicked.connect(self.import_ip_list)
        button_layout.addWidget(self.import_btn)
        
        # 导出按钮
        self.export_btn = QPushButton("导出IP列表")
        self.export_btn.clicked.connect(self.export_ip_list)
        button_layout.addWidget(self.export_btn)
        
        # 生成随机IP按钮
        self.generate_btn = QPushButton("生成随机IP")
        self.generate_btn.clicked.connect(self.generate_random_ips)
        button_layout.addWidget(self.generate_btn)
        
        # 清空按钮
        self.clear_btn = QPushButton("清空列表")
        self.clear_btn.clicked.connect(self.clear_ip_list)
        button_layout.addWidget(self.clear_btn)
        
        layout.addLayout(button_layout)
        
        # IP列表表格
        self.ip_table = QTableWidget()
        self.ip_table.setColumnCount(5)
        self.ip_table.setHorizontalHeaderLabels(["源IP", "目的IP", "协议", "源端口", "目的端口"])
        self.ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.ip_table)
        
        self.tab_widget.addTab(tab, "IP列表管理")
    
    def create_interface_tab(self):
        """创建接口管理标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 接口创建配置
        group_box = QGroupBox("Loopback接口配置")
        group_layout = QVBoxLayout(group_box)
        
        # 接口数量
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("接口数量:"))
        self.interface_count_spin = QSpinBox()
        self.interface_count_spin.setRange(1, 100)
        self.interface_count_spin.setValue(1)
        h_layout.addWidget(self.interface_count_spin)
        h_layout.addStretch()
        group_layout.addLayout(h_layout)
        
        # 基础IP
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("基础IP地址:"))
        self.base_ip_edit = QLineEdit("192.168.1.")
        h_layout.addWidget(self.base_ip_edit)
        h_layout.addStretch()
        group_layout.addLayout(h_layout)
        
        layout.addWidget(group_box)
        
        # 接口管理按钮
        button_layout = QHBoxLayout()
        
        self.create_if_btn = QPushButton("创建接口")
        self.create_if_btn.clicked.connect(self.create_interfaces)
        button_layout.addWidget(self.create_if_btn)
        
        self.delete_if_btn = QPushButton("删除接口")
        self.delete_if_btn.clicked.connect(self.delete_interfaces)
        button_layout.addWidget(self.delete_if_btn)
        
        self.list_if_btn = QPushButton("列出接口")
        self.list_if_btn.clicked.connect(self.list_interfaces)
        button_layout.addWidget(self.list_if_btn)
        
        layout.addLayout(button_layout)
        
        # 接口列表
        self.interface_table = QTableWidget()
        self.interface_table.setColumnCount(2)
        self.interface_table.setHorizontalHeaderLabels(["接口名称", "IP地址"])
        self.interface_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.interface_table)
        
        self.tab_widget.addTab(tab, "接口管理")
    
    def create_traffic_config_tab(self):
        """创建流量配置标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 流量参数配置
        group_box = QGroupBox("流量参数配置")
        group_layout = QVBoxLayout(group_box)
        
        # 流量速率
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("流量速率 (PPS):"))
        self.traffic_rate_spin = QSpinBox()
        self.traffic_rate_spin.setRange(1, 10000)
        self.traffic_rate_spin.setValue(1000)
        h_layout.addWidget(self.traffic_rate_spin)
        h_layout.addStretch()
        group_layout.addLayout(h_layout)
        
        # 数据包大小
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("数据包大小 (字节):"))
        self.packet_size_spin = QSpinBox()
        self.packet_size_spin.setRange(64, 1500)
        self.packet_size_spin.setValue(64)
        h_layout.addWidget(self.packet_size_spin)
        h_layout.addStretch()
        group_layout.addLayout(h_layout)
        
        # 测试时长
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("测试时长 (秒):"))
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(1, 3600)
        self.duration_spin.setValue(60)
        h_layout.addWidget(self.duration_spin)
        h_layout.addStretch()
        group_layout.addLayout(h_layout)
        
        # 协议选择
        h_layout = QHBoxLayout()
        h_layout.addWidget(QLabel("协议:"))
        
        self.tcp_check = QCheckBox("TCP")
        self.tcp_check.setChecked(True)
        h_layout.addWidget(self.tcp_check)
        
        self.udp_check = QCheckBox("UDP")
        self.udp_check.setChecked(True)
        h_layout.addWidget(self.udp_check)
        
        self.icmp_check = QCheckBox("ICMP")
        self.icmp_check.setChecked(True)
        h_layout.addWidget(self.icmp_check)
        
        h_layout.addStretch()
        group_layout.addLayout(h_layout)
        
        layout.addWidget(group_box)
        
        # 测试控制按钮
        control_layout = QHBoxLayout()
        
        self.start_test_btn = QPushButton("开始测试")
        self.start_test_btn.clicked.connect(self.start_test)
        control_layout.addWidget(self.start_test_btn)
        
        self.stop_test_btn = QPushButton("停止测试")
        self.stop_test_btn.clicked.connect(self.stop_test)
        self.stop_test_btn.setEnabled(False)
        control_layout.addWidget(self.stop_test_btn)
        
        layout.addLayout(control_layout)
        
        self.tab_widget.addTab(tab, "流量配置")
    
    def create_status_tab(self):
        """创建状态监控标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 状态显示
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
        self.tab_widget.addTab(tab, "状态监控")
    
    def import_ip_list(self):
        """导入IP列表"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "导入IP列表", "", "CSV Files (*.csv);;JSON Files (*.json)"
        )
        if file_path:
            try:
                ip_list = self.ip_manager.load_from_file(file_path)
                self.update_ip_table(ip_list)
                self.statusBar().showMessage(f"成功导入 {len(ip_list)} 个IP配置")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入失败: {str(e)}")
    
    def export_ip_list(self):
        """导出IP列表"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出IP列表", "", "CSV Files (*.csv);;JSON Files (*.json)"
        )
        if file_path:
            try:
                self.ip_manager.save_to_file(file_path)
                self.statusBar().showMessage(f"成功导出IP列表到 {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
    
    def generate_random_ips(self):
        """生成随机IP列表"""
        try:
            count, ok = QInputDialog.getInt(self, "生成随机IP", "请输入要生成的IP数量:", 10, 1, 1000)
            if ok:
                ip_list = self.ip_manager.generate_random_ip_list(count)
                self.update_ip_table(ip_list)
                self.statusBar().showMessage(f"成功生成 {count} 个随机IP配置")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成失败: {str(e)}")
    
    def clear_ip_list(self):
        """清空IP列表"""
        self.ip_manager.clear_ip_list()
        self.update_ip_table([])
        self.statusBar().showMessage("已清空IP列表")
    
    def update_ip_table(self, ip_list):
        """更新IP列表表格"""
        self.ip_table.setRowCount(len(ip_list))
        for row, ip_config in enumerate(ip_list):
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip_config.source_ip))
            self.ip_table.setItem(row, 1, QTableWidgetItem(ip_config.destination_ip))
            self.ip_table.setItem(row, 2, QTableWidgetItem(ip_config.protocol))
            self.ip_table.setItem(row, 3, QTableWidgetItem(str(ip_config.source_port)))
            self.ip_table.setItem(row, 4, QTableWidgetItem(str(ip_config.destination_port)))
    
    def create_interfaces(self):
        """创建Loopback接口"""
        count = self.interface_count_spin.value()
        base_ip = self.base_ip_edit.text()
        
        try:
            interfaces = self.interface_manager.create_loopback_interfaces(count, base_ip)
            self.statusBar().showMessage(f"成功创建 {len(interfaces)} 个Loopback接口")
            self.list_interfaces()
        except Exception as e:
            QMessageBox.critical(self, "错误", f"创建接口失败: {str(e)}")
    
    def delete_interfaces(self):
        """删除Loopback接口"""
        try:
            result = self.interface_manager.cleanup()
            if result:
                self.statusBar().showMessage("成功删除所有创建的接口")
                self.list_interfaces()
            else:
                self.statusBar().showMessage("删除接口失败")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"删除接口失败: {str(e)}")
    
    def list_interfaces(self):
        """列出所有网络接口"""
        try:
            interfaces = self.interface_manager.list_interfaces()
            self.interface_table.setRowCount(len(interfaces))
            for row, iface in enumerate(interfaces):
                self.interface_table.setItem(row, 0, QTableWidgetItem(iface.get("name", "")))
                # 提取IP地址
                ip_address = ""
                for key, value in iface.items():
                    if "IPv4 Address" in key:
                        ip_address = value.split(" ")[0]  # 提取IP地址部分
                        break
                self.interface_table.setItem(row, 1, QTableWidgetItem(ip_address))
        except Exception as e:
            QMessageBox.critical(self, "错误", f"列出接口失败: {str(e)}")
    
    def start_test(self):
        """开始测试"""
        # 更新配置
        self.sender_config.traffic_rate = self.traffic_rate_spin.value()
        self.sender_config.packet_size = self.packet_size_spin.value()
        self.sender_config.duration = self.duration_spin.value()
        
        # 更新协议配置
        protocols = []
        if self.tcp_check.isChecked():
            protocols.append("TCP")
        if self.udp_check.isChecked():
            protocols.append("UDP")
        if self.icmp_check.isChecked():
            protocols.append("ICMP")
        self.sender_config.protocols = protocols
        
        # 获取IP列表
        ip_list = self.ip_manager.get_ip_list()
        if not ip_list:
            QMessageBox.warning(self, "警告", "IP列表为空，请先导入或生成IP列表")
            return
        
        # 更新流量发送器配置
        self.traffic_sender = TrafficSender(self.sender_config)
        
        # 启动发送线程
        self.send_thread = TrafficSenderThread(self.traffic_sender, ip_list)
        self.send_thread.finished.connect(self.test_finished)
        self.send_thread.start()
        
        # 更新按钮状态
        self.start_test_btn.setEnabled(False)
        self.stop_test_btn.setEnabled(True)
        self.statusBar().showMessage("测试进行中...")
    
    def stop_test(self):
        """停止测试"""
        if self.send_thread:
            self.send_thread.stop()
            self.send_thread.wait()
            self.test_finished()
    
    def test_finished(self):
        """测试完成"""
        self.start_test_btn.setEnabled(True)
        self.stop_test_btn.setEnabled(False)
        self.statusBar().showMessage("测试完成")
    
    def update_status(self):
        """更新状态信息"""
        if self.traffic_sender:
            stats = self.traffic_sender.get_stats()
            status_text = f"发送数据包: {stats['sent_count']}\n"
            status_text += f"发送字节数: {stats['sent_count'] * self.sender_config.packet_size}\n"
            status_text += f"当前速率: {stats['current_rate']:.2f} PPS\n"
            self.status_text.setText(status_text)
    
    def closeEvent(self, event):
        """窗口关闭事件"""
        # 清理资源
        self.interface_manager.cleanup()
        if self.send_thread:
            self.send_thread.stop()
            self.send_thread.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SenderGUI()
    window.show()
    sys.exit(app.exec_())
