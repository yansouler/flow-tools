from scapy.all import IP, TCP, UDP, ICMP, Raw
from typing import Any, Optional
from common.config import IPConfig

class PacketGenerator:
    def __init__(self):
        pass
    
    def generate_packet(self, ip_config: IPConfig, packet_size: int = 64) -> Any:
        """根据配置生成数据包"""
        protocol = ip_config.protocol.upper()
        
        if protocol == "TCP":
            return self._generate_tcp_packet(ip_config, packet_size)
        elif protocol == "UDP":
            return self._generate_udp_packet(ip_config, packet_size)
        elif protocol == "ICMP":
            return self._generate_icmp_packet(ip_config, packet_size)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
    
    def _generate_tcp_packet(self, ip_config: IPConfig, packet_size: int = 64) -> Any:
        """生成TCP数据包"""
        # 计算需要填充的数据大小
        header_size = 20 + 20  # IP header + TCP header
        payload_size = max(0, packet_size - header_size)
        payload = b'X' * payload_size
        
        # 构造TCP数据包
        ip_layer = IP(src=ip_config.source_ip, dst=ip_config.destination_ip)
        tcp_layer = TCP(
            sport=ip_config.source_port if ip_config.source_port != 0 else None,
            dport=ip_config.destination_port if ip_config.destination_port != 0 else 80,
            flags="S"  # SYN标志
        )
        raw_layer = Raw(load=payload)
        
        return ip_layer / tcp_layer / raw_layer
    
    def _generate_udp_packet(self, ip_config: IPConfig, packet_size: int = 64) -> Any:
        """生成UDP数据包"""
        # 计算需要填充的数据大小
        header_size = 20 + 8  # IP header + UDP header
        payload_size = max(0, packet_size - header_size)
        payload = b'X' * payload_size
        
        # 构造UDP数据包
        ip_layer = IP(src=ip_config.source_ip, dst=ip_config.destination_ip)
        udp_layer = UDP(
            sport=ip_config.source_port if ip_config.source_port != 0 else None,
            dport=ip_config.destination_port if ip_config.destination_port != 0 else 53
        )
        raw_layer = Raw(load=payload)
        
        return ip_layer / udp_layer / raw_layer
    
    def _generate_icmp_packet(self, ip_config: IPConfig, packet_size: int = 64) -> Any:
        """生成ICMP数据包"""
        # 计算需要填充的数据大小
        header_size = 20 + 8  # IP header + ICMP header
        payload_size = max(0, packet_size - header_size)
        payload = b'X' * payload_size
        
        # 构造ICMP数据包
        ip_layer = IP(src=ip_config.source_ip, dst=ip_config.destination_ip)
        icmp_layer = ICMP(type=8, code=0)  # Echo Request
        raw_layer = Raw(load=payload)
        
        return ip_layer / icmp_layer / raw_layer
    
    def generate_random_packet(self, protocol: str = "TCP", packet_size: int = 64) -> Any:
        """生成随机数据包"""
        from common.utils import generate_random_ip, generate_random_port
        
        ip_config = IPConfig(
            source_ip=generate_random_ip(),
            destination_ip=generate_random_ip(),
            protocol=protocol,
            source_port=generate_random_port(),
            destination_port=generate_random_port() if protocol in ["TCP", "UDP"] else 0
        )
        
        return self.generate_packet(ip_config, packet_size)
