import unittest
import tempfile
import os
from sender.ip_manager import IPManager
from sender.packet_generator import PacketGenerator
from common.config import IPConfig, SenderConfig

class TestIPManager(unittest.TestCase):
    """测试IP管理器"""
    
    def setUp(self):
        """设置测试环境"""
        self.ip_manager = IPManager()
    
    def test_add_valid_ip_config(self):
        """测试添加有效的IP配置"""
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="TCP",
            source_port=12345,
            destination_port=80
        )
        result = self.ip_manager.add_ip_config(ip_config)
        self.assertTrue(result)
        self.assertEqual(len(self.ip_manager.get_ip_list()), 1)
    
    def test_add_invalid_ip_config(self):
        """测试添加无效的IP配置"""
        # 无效的源IP
        ip_config = IPConfig(
            source_ip="invalid_ip",
            destination_ip="10.0.0.1",
            protocol="TCP"
        )
        result = self.ip_manager.add_ip_config(ip_config)
        self.assertFalse(result)
        self.assertEqual(len(self.ip_manager.get_ip_list()), 0)
        
        # 无效的协议
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="INVALID"
        )
        result = self.ip_manager.add_ip_config(ip_config)
        self.assertFalse(result)
        self.assertEqual(len(self.ip_manager.get_ip_list()), 0)
    
    def test_generate_random_ip_list(self):
        """测试生成随机IP列表"""
        count = 5
        ip_list = self.ip_manager.generate_random_ip_list(count)
        self.assertEqual(len(ip_list), count)
        
        # 验证每个IP配置都是有效的
        for ip_config in ip_list:
            self.assertTrue(self.ip_manager._validate_ip_config(ip_config))
    
    def test_save_and_load_ip_list(self):
        """测试保存和加载IP列表"""
        # 创建临时文件
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            temp_file = f.name
        
        try:
            # 添加一些IP配置
            ip_configs = [
                IPConfig("192.168.1.1", "10.0.0.1", "TCP", 12345, 80),
                IPConfig("192.168.1.2", "10.0.0.2", "UDP", 54321, 53)
            ]
            
            for ip_config in ip_configs:
                self.ip_manager.add_ip_config(ip_config)
            
            # 保存到文件
            self.ip_manager.save_to_file(temp_file)
            
            # 创建新的IP管理器并加载文件
            new_ip_manager = IPManager()
            loaded_ip_list = new_ip_manager.load_from_file(temp_file)
            
            # 验证加载的IP列表与原始列表相同
            self.assertEqual(len(loaded_ip_list), len(ip_configs))
        finally:
            # 清理临时文件
            os.unlink(temp_file)

class TestPacketGenerator(unittest.TestCase):
    """测试数据包生成器"""
    
    def setUp(self):
        """设置测试环境"""
        self.packet_generator = PacketGenerator()
    
    def test_generate_tcp_packet(self):
        """测试生成TCP数据包"""
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="TCP",
            source_port=12345,
            destination_port=80
        )
        
        packet = self.packet_generator.generate_packet(ip_config, packet_size=64)
        
        # 验证数据包基本结构
        self.assertIsNotNone(packet)
        self.assertEqual(packet[0][1].src, ip_config.source_ip)
        self.assertEqual(packet[0][1].dst, ip_config.destination_ip)
        self.assertEqual(packet[0][2].sport, ip_config.source_port)
        self.assertEqual(packet[0][2].dport, ip_config.destination_port)
    
    def test_generate_udp_packet(self):
        """测试生成UDP数据包"""
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="UDP",
            source_port=12345,
            destination_port=53
        )
        
        packet = self.packet_generator.generate_packet(ip_config, packet_size=64)
        
        # 验证数据包基本结构
        self.assertIsNotNone(packet)
        self.assertEqual(packet[0][1].src, ip_config.source_ip)
        self.assertEqual(packet[0][1].dst, ip_config.destination_ip)
        self.assertEqual(packet[0][2].sport, ip_config.source_port)
        self.assertEqual(packet[0][2].dport, ip_config.destination_port)
    
    def test_generate_icmp_packet(self):
        """测试生成ICMP数据包"""
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="ICMP"
        )
        
        packet = self.packet_generator.generate_packet(ip_config, packet_size=64)
        
        # 验证数据包基本结构
        self.assertIsNotNone(packet)
        self.assertEqual(packet[0][1].src, ip_config.source_ip)
        self.assertEqual(packet[0][1].dst, ip_config.destination_ip)
    
    def test_generate_random_packet(self):
        """测试生成随机数据包"""
        packet = self.packet_generator.generate_random_packet(protocol="TCP", packet_size=64)
        self.assertIsNotNone(packet)
        
        packet = self.packet_generator.generate_random_packet(protocol="UDP", packet_size=64)
        self.assertIsNotNone(packet)
        
        packet = self.packet_generator.generate_random_packet(protocol="ICMP", packet_size=64)
        self.assertIsNotNone(packet)

class TestSenderConfig(unittest.TestCase):
    """测试发送端配置"""
    
    def test_default_config(self):
        """测试默认配置"""
        config = SenderConfig()
        self.assertEqual(config.traffic_rate, 1000)
        self.assertEqual(config.packet_size, 64)
        self.assertEqual(config.duration, 60)
        self.assertEqual(config.protocols, ["TCP", "UDP", "ICMP"])
    
    def test_custom_config(self):
        """测试自定义配置"""
        config = SenderConfig(
            traffic_rate=500,
            packet_size=128,
            duration=30,
            protocols=["TCP", "UDP"]
        )
        self.assertEqual(config.traffic_rate, 500)
        self.assertEqual(config.packet_size, 128)
        self.assertEqual(config.duration, 30)
        self.assertEqual(config.protocols, ["TCP", "UDP"])

if __name__ == "__main__":
    unittest.main()