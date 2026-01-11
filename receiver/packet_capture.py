import time
import threading
from queue import Queue
from typing import List, Optional, Callable
from scapy.all import sniff, conf
from common.config import ReceiverConfig

class PacketCapture:
    def __init__(self, config: ReceiverConfig):
        self.config = config
        self.is_capturing = False
        self.packet_queue = Queue(maxsize=10000)  # 设置队列大小限制
        self.capture_thread = None
        self.packet_handler: Optional[Callable] = None
        self.captured_count = 0
        
    def start_capture(self, packet_handler: Optional[Callable] = None) -> None:
        """开始捕获数据包"""
        if self.is_capturing:
            return
        
        self.is_capturing = True
        self.packet_handler = packet_handler
        self.captured_count = 0
        
        # 创建并启动捕获线程
        self.capture_thread = threading.Thread(target=self._capture_worker)
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def _capture_worker(self) -> None:
        """捕获线程工作函数"""
        try:
            # 设置捕获参数
            capture_filter = self.config.filter_rule
            interface = self.config.capture_interface if self.config.capture_interface else conf.iface
            
            # 开始捕获数据包
            sniff(
                iface=interface,
                filter=capture_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            print(f"Error during packet capture: {e}")
            self.is_capturing = False
    
    def _process_packet(self, packet) -> None:
        """处理捕获到的数据包"""
        self.captured_count += 1
        
        # 如果设置了数据包处理器，直接调用
        if self.packet_handler:
            self.packet_handler(packet)
        else:
            # 否则将数据包放入队列
            try:
                self.packet_queue.put(packet, block=False)
            except Queue.Full:
                # 队列已满，丢弃最旧的数据包
                if not self.packet_queue.empty():
                    self.packet_queue.get(block=False)
                self.packet_queue.put(packet, block=False)
    
    def stop_capture(self) -> None:
        """停止捕获数据包"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
    
    def get_packet(self, timeout: float = None) -> Optional[any]:
        """从队列获取数据包"""
        try:
            return self.packet_queue.get(timeout=timeout)
        except Exception:
            return None
    
    def get_captured_count(self) -> int:
        """获取已捕获的数据包数量"""
        return self.captured_count
    
    def clear_queue(self) -> None:
        """清空数据包队列"""
        while not self.packet_queue.empty():
            self.packet_queue.get(block=False)
    
    def set_filter(self, filter_rule: str) -> None:
        """设置捕获过滤规则"""
        self.config.filter_rule = filter_rule
        # 如果正在捕获，需要重启捕获以应用新规则
        if self.is_capturing:
            self.stop_capture()
            self.start_capture(self.packet_handler)
    
    def set_interface(self, interface: str) -> None:
        """设置捕获接口"""
        self.config.capture_interface = interface
        # 如果正在捕获，需要重启捕获以应用新接口
        if self.is_capturing:
            self.stop_capture()
            self.start_capture(self.packet_handler)
