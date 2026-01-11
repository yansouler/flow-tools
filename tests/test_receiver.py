import unittest
from receiver.packet_parser import PacketParser, ParsedPacket
from receiver.traffic_analyzer import TrafficAnalyzer
from receiver.nat_analyzer import NATAnalyzer
from sender.packet_generator import PacketGenerator
from common.config import IPConfig

class TestPacketParser(unittest.TestCase):
    """测试数据包解析器"""
    
    def setUp(self):
        """设置测试环境"""
        self.parser = PacketParser()
        self.generator = PacketGenerator()
    
    def test_parse_tcp_packet(self):
        """测试解析TCP数据包"""
        # 生成一个TCP数据包
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="TCP",
            source_port=12345,
            destination_port=80
        )
        packet = self.generator.generate_packet(ip_config, packet_size=64)
        
        # 解析数据包
        parsed_packet = self.parser.parse_packet(packet)
        
        # 验证解析结果
        self.assertIsInstance(parsed_packet, ParsedPacket)
        self.assertEqual(parsed_packet.protocol, "TCP")
        self.assertEqual(parsed_packet.source_ip, "192.168.1.1")
        self.assertEqual(parsed_packet.destination_ip, "10.0.0.1")
        self.assertEqual(parsed_packet.source_port, 12345)
        self.assertEqual(parsed_packet.destination_port, 80)
        self.assertGreater(parsed_packet.packet_size, 0)
    
    def test_parse_udp_packet(self):
        """测试解析UDP数据包"""
        # 生成一个UDP数据包
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="UDP",
            source_port=12345,
            destination_port=53
        )
        packet = self.generator.generate_packet(ip_config, packet_size=64)
        
        # 解析数据包
        parsed_packet = self.parser.parse_packet(packet)
        
        # 验证解析结果
        self.assertIsInstance(parsed_packet, ParsedPacket)
        self.assertEqual(parsed_packet.protocol, "UDP")
        self.assertEqual(parsed_packet.source_ip, "192.168.1.1")
        self.assertEqual(parsed_packet.destination_ip, "10.0.0.1")
        self.assertEqual(parsed_packet.source_port, 12345)
        self.assertEqual(parsed_packet.destination_port, 53)
    
    def test_parse_icmp_packet(self):
        """测试解析ICMP数据包"""
        # 生成一个ICMP数据包
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="ICMP"
        )
        packet = self.generator.generate_packet(ip_config, packet_size=64)
        
        # 解析数据包
        parsed_packet = self.parser.parse_packet(packet)
        
        # 验证解析结果
        self.assertIsInstance(parsed_packet, ParsedPacket)
        self.assertEqual(parsed_packet.protocol, "ICMP")
        self.assertEqual(parsed_packet.source_ip, "192.168.1.1")
        self.assertEqual(parsed_packet.destination_ip, "10.0.0.1")
        self.assertEqual(parsed_packet.source_port, 0)  # ICMP没有端口
        self.assertEqual(parsed_packet.destination_port, 0)  # ICMP没有端口
    
    def test_get_packet_summary(self):
        """测试获取数据包摘要"""
        # 生成一个TCP数据包
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="TCP",
            source_port=12345,
            destination_port=80
        )
        packet = self.generator.generate_packet(ip_config, packet_size=64)
        parsed_packet = self.parser.parse_packet(packet)
        
        summary = self.parser.get_packet_summary(parsed_packet)
        self.assertIsInstance(summary, str)
        self.assertIn("TCP", summary)
        self.assertIn("192.168.1.1", summary)
        self.assertIn("10.0.0.1", summary)

class TestTrafficAnalyzer(unittest.TestCase):
    """测试流量分析器"""
    
    def setUp(self):
        """设置测试环境"""
        self.analyzer = TrafficAnalyzer()
        self.parser = PacketParser()
        self.generator = PacketGenerator()
    
    def test_add_packet(self):
        """测试添加数据包进行分析"""
        # 生成并解析一个TCP数据包
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="TCP",
            source_port=12345,
            destination_port=80
        )
        packet = self.generator.generate_packet(ip_config, packet_size=64)
        parsed_packet = self.parser.parse_packet(packet)
        
        # 添加到分析器
        self.analyzer.add_parsed_packet(parsed_packet)
        
        # 验证统计结果
        stats = self.analyzer.get_stats()
        self.assertEqual(stats["total_packets"], 1)
        self.assertEqual(stats["protocol_stats"]["TCP"]["count"], 1)
    
    def test_multiple_packets(self):
        """测试分析多个数据包"""
        # 生成多个不同类型的数据包
        ip_configs = [
            IPConfig("192.168.1.1", "10.0.0.1", "TCP", 12345, 80),
            IPConfig("192.168.1.2", "10.0.0.2", "UDP", 54321, 53),
            IPConfig("192.168.1.3", "10.0.0.3", "ICMP"),
            IPConfig("192.168.1.1", "10.0.0.1", "TCP", 12345, 443)
        ]
        
        for ip_config in ip_configs:
            packet = self.generator.generate_packet(ip_config, packet_size=64)
            parsed_packet = self.parser.parse_packet(packet)
            self.analyzer.add_parsed_packet(parsed_packet)
        
        # 验证统计结果
        stats = self.analyzer.get_stats()
        self.assertEqual(stats["total_packets"], 4)
        self.assertEqual(stats["protocol_stats"]["TCP"]["count"], 2)
        self.assertEqual(stats["protocol_stats"]["UDP"]["count"], 1)
        self.assertEqual(stats["protocol_stats"]["ICMP"]["count"], 1)
    
    def test_protocol_distribution(self):
        """测试协议分布"""
        # 生成多个不同类型的数据包
        ip_configs = [
            IPConfig("192.168.1.1", "10.0.0.1", "TCP"),
            IPConfig("192.168.1.2", "10.0.0.2", "TCP"),
            IPConfig("192.168.1.3", "10.0.0.3", "UDP"),
            IPConfig("192.168.1.4", "10.0.0.4", "ICMP")
        ]
        
        for ip_config in ip_configs:
            packet = self.generator.generate_packet(ip_config, packet_size=64)
            parsed_packet = self.parser.parse_packet(packet)
            self.analyzer.add_parsed_packet(parsed_packet)
        
        # 获取协议分布
        distribution = self.analyzer.get_protocol_distribution()
        
        # 验证分布结果
        self.assertAlmostEqual(distribution["TCP"], 50.0)
        self.assertAlmostEqual(distribution["UDP"], 25.0)
        self.assertAlmostEqual(distribution["ICMP"], 25.0)
    
    def test_generate_report(self):
        """测试生成报告"""
        # 生成一些数据包
        ip_config = IPConfig(
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="TCP"
        )
        packet = self.generator.generate_packet(ip_config, packet_size=64)
        parsed_packet = self.parser.parse_packet(packet)
        self.analyzer.add_parsed_packet(parsed_packet)
        
        # 生成报告
        report = self.analyzer.generate_report()
        
        # 验证报告结构
        self.assertIn("summary", report)
        self.assertIn("protocol_breakdown", report)
        self.assertIn("top_source_ips", report)
        self.assertIn("top_destination_ips", report)

class TestNATAnalyzer(unittest.TestCase):
    """测试NAT分析器"""
    
    def setUp(self):
        """设置测试环境"""
        self.nat_analyzer = NATAnalyzer()
    
    def test_is_internal_ip(self):
        """测试判断内部IP"""
        # 测试内部IP
        self.assertTrue(self.nat_analyzer.is_internal_ip("10.0.0.1"))
        self.assertTrue(self.nat_analyzer.is_internal_ip("172.16.0.1"))
        self.assertTrue(self.nat_analyzer.is_internal_ip("192.168.1.1"))
        
        # 测试外部IP
        self.assertFalse(self.nat_analyzer.is_internal_ip("8.8.8.8"))
        self.assertFalse(self.nat_analyzer.is_internal_ip("1.1.1.1"))
        self.assertFalse(self.nat_analyzer.is_internal_ip("203.0.113.1"))
    
    def test_nat_detection(self):
        """测试NAT检测"""
        # 创建模拟的解析数据包
        # 内部到外部的连接
        internal_to_external = ParsedPacket(
            timestamp=1234567890.0,
            source_ip="192.168.1.1",
            destination_ip="8.8.8.8",
            protocol="TCP",
            source_port=12345,
            destination_port=80,
            packet_size=64
        )
        
        # 外部到内部的连接（模拟NAT转换）
        external_to_internal = ParsedPacket(
            timestamp=1234567890.1,
            source_ip="8.8.8.8",
            destination_ip="192.168.1.100",  # 注意：这里使用不同的内部IP模拟NAT转换
            protocol="TCP",
            source_port=80,
            destination_port=54321,
            packet_size=64
        )
        
        # 分析数据包
        self.nat_analyzer.analyze_packet(internal_to_external)
        self.nat_analyzer.analyze_packet(external_to_internal)
        
        # 检测NAT存在
        self.assertTrue(self.nat_analyzer.detect_nat_presence())
        
        # 获取NAT类型
        nat_type = self.nat_analyzer.identify_nat_type()
        self.assertIsInstance(nat_type, str)
    
    def test_generate_nat_report(self):
        """测试生成NAT报告"""
        # 创建模拟的解析数据包
        internal_to_external = ParsedPacket(
            timestamp=1234567890.0,
            source_ip="192.168.1.1",
            destination_ip="8.8.8.8",
            protocol="TCP",
            source_port=12345,
            destination_port=80,
            packet_size=64
        )
        
        external_to_internal = ParsedPacket(
            timestamp=1234567890.1,
            source_ip="8.8.8.8",
            destination_ip="192.168.1.100",
            protocol="TCP",
            source_port=80,
            destination_port=54321,
            packet_size=64
        )
        
        # 分析数据包
        self.nat_analyzer.analyze_packet(internal_to_external)
        self.nat_analyzer.analyze_packet(external_to_internal)
        
        # 生成报告
        report = self.nat_analyzer.generate_nat_report()
        
        # 验证报告结构
        self.assertIn("nat_present", report)
        self.assertIn("nat_type", report)
        self.assertIn("mappings", report)
        self.assertTrue(report["nat_present"])

if __name__ == "__main__":
    unittest.main()