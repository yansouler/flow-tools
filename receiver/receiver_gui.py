import sys
import os
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QFileDialog, QLineEdit,
    QLabel, QSpinBox, QCheckBox, QGroupBox, QComboBox, QMessageBox,
    QProgressBar, QTextEdit, QHeaderView, QSplitter, QFormLayout
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont
from PySide6 import QtWidgets

# 导入matplotlib相关模块
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import numpy as np

from receiver.packet_capture import PacketCapture
from receiver.packet_parser import PacketParser
from receiver.traffic_analyzer import TrafficAnalyzer
from receiver.nat_analyzer import NATAnalyzer
from common.config import ReceiverConfig

class PacketCaptureThread(QThread):
    """数据包捕获线程"""
    packet_received = Signal(object)
    
    def __init__(self, packet_capture):
        super().__init__()
        self.packet_capture = packet_capture
    
    def run(self):
        """线程运行函数"""
        # 定义数据包处理函数
        def handle_packet(packet):
            self.packet_received.emit(packet)
        
        # 开始捕获
        self.packet_capture.start_capture(handle_packet)

class ReceiverGUI(QMainWindow):
    """接收端主界面"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("网络流量生成工具 - 接收端")
        self.setGeometry(100, 100, 1200, 800)
        
        # 初始化组件
        self.receiver_config = ReceiverConfig()
        self.packet_capture = PacketCapture(self.receiver_config)
        self.packet_parser = PacketParser()
        self.traffic_analyzer = TrafficAnalyzer()
        self.nat_analyzer = NATAnalyzer()
        
        # 捕获线程
        self.capture_thread = None
        self.is_capturing = False
        
        # 创建主布局
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # 创建标签页
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # 创建各个标签页
        self.create_capture_config_tab()
        self.create_real_time_monitor_tab()
        self.create_traffic_analysis_tab()
        self.create_nat_analysis_tab()
        self.create_report_tab()
        
        # 创建底部状态栏
        self.statusBar().showMessage("就绪")
        
        # 创建定时器用于更新状态
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)  # 每秒更新一次
    
    def create_capture_config_tab(self):
        """创建捕获配置标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 捕获接口配置
        group_box = QGroupBox("捕获配置")
        group_layout = QFormLayout(group_box)
        
        # 接口选择
        self.interface_combo = QComboBox()
        # 这里应该填充可用的网络接口
        self.interface_combo.addItem("自动选择")
        self.interface_combo.addItem("eth0")
        self.interface_combo.addItem("wlan0")
        self.interface_combo.addItem("lo")
        group_layout.addRow(QLabel("网络接口:"), self.interface_combo)
        
        # 过滤规则
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("例如: tcp port 80")
        group_layout.addRow(QLabel("过滤规则:"), self.filter_edit)
        
        # 保存路径
        save_layout = QHBoxLayout()
        self.save_path_edit = QLineEdit()
        self.save_path_edit.setPlaceholderText("选择保存路径")
        save_button = QPushButton("浏览")
        save_button.clicked.connect(self.browse_save_path)
        save_layout.addWidget(self.save_path_edit)
        save_layout.addWidget(save_button)
        group_layout.addRow(QLabel("保存路径:"), save_layout)
        
        layout.addWidget(group_box)
        
        # 捕获控制按钮
        control_layout = QHBoxLayout()
        
        self.start_capture_btn = QPushButton("开始捕获")
        self.start_capture_btn.clicked.connect(self.start_capture)
        control_layout.addWidget(self.start_capture_btn)
        
        self.stop_capture_btn = QPushButton("停止捕获")
        self.stop_capture_btn.clicked.connect(self.stop_capture)
        self.stop_capture_btn.setEnabled(False)
        control_layout.addWidget(self.stop_capture_btn)
        
        self.clear_stats_btn = QPushButton("清空统计")
        self.clear_stats_btn.clicked.connect(self.clear_statistics)
        control_layout.addWidget(self.clear_stats_btn)
        
        layout.addLayout(control_layout)
        
        self.tab_widget.addTab(tab, "捕获配置")
    
    def create_real_time_monitor_tab(self):
        """创建实时监控标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 分割器，用于分隔表格和状态
        splitter = QSplitter(Qt.Vertical)
        
        # 实时数据包表格
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels([
            "时间", "源IP", "源端口", "目的IP", "目的端口", "协议", "大小"
        ])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.setMaximumHeight(300)
        splitter.addWidget(self.packet_table)
        
        # 实时统计信息
        stats_group = QGroupBox("实时统计")
        stats_layout = QHBoxLayout(stats_group)
        
        # 左侧统计
        left_stats = QVBoxLayout()
        self.total_packets_label = QLabel("总数据包: 0")
        self.total_bytes_label = QLabel("总字节数: 0")
        self.packet_rate_label = QLabel("数据包速率: 0 PPS")
        left_stats.addWidget(self.total_packets_label)
        left_stats.addWidget(self.total_bytes_label)
        left_stats.addWidget(self.packet_rate_label)
        stats_layout.addLayout(left_stats)
        
        # 右侧统计
        right_stats = QVBoxLayout()
        self.tcp_count_label = QLabel("TCP: 0")
        self.udp_count_label = QLabel("UDP: 0")
        self.icmp_count_label = QLabel("ICMP: 0")
        right_stats.addWidget(self.tcp_count_label)
        right_stats.addWidget(self.udp_count_label)
        right_stats.addWidget(self.icmp_count_label)
        stats_layout.addLayout(right_stats)
        
        splitter.addWidget(stats_group)
        layout.addWidget(splitter)
        
        self.tab_widget.addTab(tab, "实时监控")
    
    def create_traffic_analysis_tab(self):
        """创建流量分析标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 分割器，用于分隔不同的图表
        splitter = QSplitter(Qt.Vertical)
        
        # 协议分布图表
        protocol_group = QGroupBox("协议分布")
        protocol_layout = QVBoxLayout(protocol_group)
        
        self.protocol_fig = Figure(figsize=(8, 4), dpi=100)
        self.protocol_canvas = FigureCanvas(self.protocol_fig)
        protocol_layout.addWidget(self.protocol_canvas)
        splitter.addWidget(protocol_group)
        
        # 流量趋势图表
        trend_group = QGroupBox("流量趋势")
        trend_layout = QVBoxLayout(trend_group)
        
        self.trend_fig = Figure(figsize=(8, 4), dpi=100)
        self.trend_canvas = FigureCanvas(self.trend_fig)
        trend_layout.addWidget(self.trend_canvas)
        splitter.addWidget(trend_group)
        
        layout.addWidget(splitter)
        
        self.tab_widget.addTab(tab, "流量分析")
    
    def create_nat_analysis_tab(self):
        """创建NAT分析标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # NAT状态显示
        nat_status_group = QGroupBox("NAT状态")
        nat_status_layout = QVBoxLayout(nat_status_group)
        
        self.nat_present_label = QLabel("NAT存在: 未知")
        self.nat_type_label = QLabel("NAT类型: 未知")
        self.nat_mappings_label = QLabel("NAT映射数量: 0")
        
        nat_status_layout.addWidget(self.nat_present_label)
        nat_status_layout.addWidget(self.nat_type_label)
        nat_status_layout.addWidget(self.nat_mappings_label)
        
        layout.addWidget(nat_status_group)
        
        # NAT映射表
        self.nat_mapping_table = QTableWidget()
        self.nat_mapping_table.setColumnCount(3)
        self.nat_mapping_table.setHorizontalHeaderLabels(["内部地址", "外部地址", "转换后内部地址"])
        self.nat_mapping_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.nat_mapping_table)
        
        self.tab_widget.addTab(tab, "NAT分析")
    
    def create_report_tab(self):
        """创建报告标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 报告生成按钮
        button_layout = QHBoxLayout()
        
        self.generate_report_btn = QPushButton("生成分析报告")
        self.generate_report_btn.clicked.connect(self.generate_report)
        button_layout.addWidget(self.generate_report_btn)
        
        self.export_report_btn = QPushButton("导出报告")
        self.export_report_btn.clicked.connect(self.export_report)
        button_layout.addWidget(self.export_report_btn)
        
        layout.addLayout(button_layout)
        
        # 报告内容显示
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        layout.addWidget(self.report_text)
        
        self.tab_widget.addTab(tab, "报告生成")
    
    def browse_save_path(self):
        """浏览保存路径"""
        save_path = QFileDialog.getExistingDirectory(self, "选择保存路径")
        if save_path:
            self.save_path_edit.setText(save_path)
            self.receiver_config.save_path = save_path
    
    def start_capture(self):
        """开始捕获"""
        # 更新配置
        interface = self.interface_combo.currentText()
        if interface != "自动选择":
            self.receiver_config.capture_interface = interface
        else:
            self.receiver_config.capture_interface = ""
        
        self.receiver_config.filter_rule = self.filter_edit.text()
        self.receiver_config.save_path = self.save_path_edit.text()
        
        # 重置分析器
        self.traffic_analyzer.reset_stats()
        self.nat_analyzer.reset_analyzer()
        
        # 清空表格
        self.packet_table.setRowCount(0)
        
        # 创建并启动捕获线程
        self.capture_thread = PacketCaptureThread(self.packet_capture)
        self.capture_thread.packet_received.connect(self.handle_packet)
        self.capture_thread.start()
        
        self.is_capturing = True
        
        # 更新按钮状态
        self.start_capture_btn.setEnabled(False)
        self.stop_capture_btn.setEnabled(True)
        self.statusBar().showMessage("捕获进行中...")
    
    def stop_capture(self):
        """停止捕获"""
        self.packet_capture.stop_capture()
        if self.capture_thread:
            self.capture_thread.wait()
        
        self.is_capturing = False
        
        # 更新按钮状态
        self.start_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
        self.statusBar().showMessage("捕获已停止")
    
    def handle_packet(self, packet):
        """处理捕获到的数据包"""
        # 解析数据包
        parsed_packet = self.packet_parser.parse_packet(packet)
        if not parsed_packet:
            return
        
        # 更新流量分析
        self.traffic_analyzer.add_parsed_packet(parsed_packet)
        
        # 更新NAT分析
        self.nat_analyzer.analyze_packet(parsed_packet)
        
        # 更新实时监控表格
        self.update_packet_table(parsed_packet)
    
    def update_packet_table(self, parsed_packet):
        """更新数据包表格"""
        # 插入新行
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        # 填充数据
        self.packet_table.setItem(row, 0, QTableWidgetItem(f"{parsed_packet.timestamp:.3f}"))
        self.packet_table.setItem(row, 1, QTableWidgetItem(parsed_packet.source_ip))
        self.packet_table.setItem(row, 2, QTableWidgetItem(str(parsed_packet.source_port)))
        self.packet_table.setItem(row, 3, QTableWidgetItem(parsed_packet.destination_ip))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(parsed_packet.destination_port)))
        self.packet_table.setItem(row, 5, QTableWidgetItem(parsed_packet.protocol))
        self.packet_table.setItem(row, 6, QTableWidgetItem(str(parsed_packet.packet_size)))
        
        # 滚动到最新行
        self.packet_table.scrollToBottom()
        
        # 限制表格行数
        if self.packet_table.rowCount() > 1000:
            self.packet_table.removeRow(0)
    
    def update_status(self):
        """更新状态信息"""
        # 更新实时统计
        stats = self.traffic_analyzer.get_stats()
        
        self.total_packets_label.setText(f"总数据包: {stats['total_packets']}")
        self.total_bytes_label.setText(f"总字节数: {stats['total_bytes']}")
        self.packet_rate_label.setText(f"数据包速率: {stats['packet_rate']:.2f} PPS")
        
        # 更新协议统计
        proto_stats = stats['protocol_stats']
        self.tcp_count_label.setText(f"TCP: {proto_stats.get('TCP', {}).get('count', 0)}")
        self.udp_count_label.setText(f"UDP: {proto_stats.get('UDP', {}).get('count', 0)}")
        self.icmp_count_label.setText(f"ICMP: {proto_stats.get('ICMP', {}).get('count', 0)}")
        
        # 更新图表
        self.update_protocol_chart()
        self.update_trend_chart()
        
        # 更新NAT状态
        self.update_nat_status()
    
    def update_protocol_chart(self):
        """更新协议分布图表"""
        protocol_dist = self.traffic_analyzer.get_protocol_distribution()
        
        # 清空图表
        self.protocol_fig.clear()
        ax = self.protocol_fig.add_subplot(111)
        
        if protocol_dist:
            labels = list(protocol_dist.keys())
            sizes = list(protocol_dist.values())
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')  # 确保饼图是圆形
        
        ax.set_title('协议分布')
        self.protocol_canvas.draw()
    
    def update_trend_chart(self):
        """更新流量趋势图表"""
        time_series = self.traffic_analyzer.get_time_series_data()
        
        # 清空图表
        self.trend_fig.clear()
        ax = self.trend_fig.add_subplot(111)
        
        if time_series['timestamps']:
            ax.plot(
                time_series['timestamps'], 
                time_series['packet_counts'], 
                label='数据包数量'
            )
            ax.set_xlabel('时间')
            ax.set_ylabel('数据包数量')
            ax.set_title('流量趋势')
            ax.legend()
            ax.grid(True)
        
        self.trend_canvas.draw()
    
    def update_nat_status(self):
        """更新NAT状态"""
        nat_stats = self.nat_analyzer.get_nat_stats()
        
        self.nat_present_label.setText(f"NAT存在: {'是' if nat_stats['nat_present'] else '否'}")
        self.nat_type_label.setText(f"NAT类型: {nat_stats['nat_type'] or '未知'}")
        self.nat_mappings_label.setText(f"NAT映射数量: {nat_stats['mapping_count']}")
        
        # 更新NAT映射表
        mappings = self.nat_analyzer.get_nat_mappings()
        self.nat_mapping_table.setRowCount(0)
        
        for session_key, mapping in mappings.items():
            if "internal" in mapping and "external" in mapping:
                row = self.nat_mapping_table.rowCount()
                self.nat_mapping_table.insertRow(row)
                self.nat_mapping_table.setItem(row, 0, QTableWidgetItem(mapping.get("internal", "")))
                self.nat_mapping_table.setItem(row, 1, QTableWidgetItem(mapping.get("external", "")))
                self.nat_mapping_table.setItem(row, 2, QTableWidgetItem(mapping.get("translated_internal", "")))
    
    def clear_statistics(self):
        """清空统计信息"""
        self.traffic_analyzer.reset_stats()
        self.nat_analyzer.reset_analyzer()
        self.packet_table.setRowCount(0)
        self.report_text.clear()
        self.statusBar().showMessage("统计信息已清空")
    
    def generate_report(self):
        """生成分析报告"""
        # 生成流量分析报告
        traffic_report = self.traffic_analyzer.generate_report()
        nat_report = self.nat_analyzer.generate_nat_report()
        
        # 格式化报告
        report_content = "# 网络流量分析报告\n\n"
        
        # 摘要信息
        report_content += "## 摘要\n"
        report_content += f"开始时间: {traffic_report['summary']['start_time']:.3f}\n"
        report_content += f"结束时间: {traffic_report['summary']['end_time']:.3f}\n"
        report_content += f"持续时间: {traffic_report['summary']['elapsed_time']:.2f}秒\n"
        report_content += f"总数据包: {traffic_report['summary']['total_packets']}\n"
        report_content += f"总字节数: {traffic_report['summary']['total_bytes']}\n"
        report_content += f"平均速率: {traffic_report['summary']['packet_rate']:.2f} PPS\n\n"
        
        # 协议分布
        report_content += "## 协议分布\n"
        for proto, stats in traffic_report['protocol_breakdown'].items():
            report_content += f"- {proto}: {stats['count']}个数据包 ({stats['bytes']}字节)\n"
        
        # NAT分析
        report_content += "\n## NAT分析\n"
        report_content += f"NAT存在: {'是' if nat_report['nat_present'] else '否'}\n"
        report_content += f"NAT类型: {nat_report['nat_type'] or '未知'}\n"
        report_content += f"NAT映射数: {nat_report['total_mappings']}\n\n"
        
        # 保存报告内容
        self.report_text.setText(report_content)
    
    def export_report(self):
        """导出报告"""
        if not self.report_text.toPlainText():
            QMessageBox.warning(self, "警告", "没有可导出的报告内容")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出报告", "", "文本文件 (*.txt);;Markdown文件 (*.md)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.report_text.toPlainText())
                self.statusBar().showMessage(f"报告已导出到 {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出报告失败: {str(e)}")
    
    def closeEvent(self, event):
        """窗口关闭事件"""
        # 停止捕获
        if self.is_capturing:
            self.stop_capture()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ReceiverGUI()
    window.show()
    sys.exit(app.exec_())
