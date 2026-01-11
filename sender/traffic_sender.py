import time
import threading
from queue import Queue
from typing import List, Optional
from scapy.all import send, sendp
from sender.packet_generator import PacketGenerator
from common.config import IPConfig, SenderConfig

class TrafficSender:
    def __init__(self, config: SenderConfig):
        self.config = config
        self.packet_generator = PacketGenerator()
        self.is_running = False
        self.thread_count = 4
        self.packet_queue = Queue()
        self.sent_count = 0
        self.start_time = 0
    
    def start_sending(self, ip_list: List[IPConfig]) -> None:
        """开始发送流量"""
        self.is_running = True
        self.sent_count = 0
        self.start_time = time.time()
        
        # 创建并启动发送线程
        threads = []
        for i in range(self.thread_count):
            t = threading.Thread(target=self._send_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 计算每个数据包的发送间隔（纳秒）
        interval_ns = 1_000_000_000 / self.config.traffic_rate
        
        # 填充数据包队列
        end_time = time.time() + self.config.duration
        while self.is_running and time.time() < end_time:
            for ip_config in ip_list:
                if not self.is_running:
                    break
                
                # 生成数据包
                packet = self.packet_generator.generate_packet(
                    ip_config, 
                    self.config.packet_size
                )
                
                # 将数据包放入队列
                self.packet_queue.put(packet)
                
                # 控制发送速率
                time.sleep(interval_ns / 1_000_000_000)
        
        # 等待所有数据包发送完成
        self.packet_queue.join()
        self.is_running = False
    
    def _send_worker(self) -> None:
        """发送线程工作函数"""
        while self.is_running or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                # 发送数据包
                send(packet, verbose=False)
                self.sent_count += 1
                self.packet_queue.task_done()
            except Exception as e:
                print(f"Error sending packet: {e}")
                self.packet_queue.task_done()
    
    def stop_sending(self) -> None:
        """停止发送流量"""
        self.is_running = False
    
    def get_stats(self) -> dict:
        """获取发送统计信息"""
        elapsed = time.time() - self.start_time if self.start_time > 0 else 0
        return {
            "sent_count": self.sent_count,
            "elapsed_time": elapsed,
            "current_rate": self.sent_count / elapsed if elapsed > 0 else 0
        }
    
    def send_burst(self, ip_list: List[IPConfig], count: int) -> int:
        """发送突发流量"""
        """发送突发流量"""
        sent = 0
        for i in range(count):
            for ip_config in ip_list:
                try:
                    packet = self.packet_generator.generate_packet(
                        ip_config, 
                        self.config.packet_size
                    )
                    send(packet, verbose=False)
                    sent += 1
                except Exception as e:
                    print(f"Error sending burst packet: {e}")
        return sent
