from dataclasses import dataclass
from typing import Dict, Any, Optional
from scapy.all import IP, TCP, UDP, ICMP, Packet

@dataclass
class ParsedPacket:
    """解析后的数据包信息"""
    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int = 0
    destination_port: int = 0
    packet_size: int = 0
    icmp_type: int = 0
    icmp_code: int = 0
    tcp_flags: str = ""
    payload_size: int = 0
    raw_data: Optional[bytes] = None

class PacketParser:
    def __init__(self):
        pass
    
    def parse_packet(self, packet: Packet, timestamp: float = None) -> Optional[ParsedPacket]:
        """解析数据包"""
        if timestamp is None:
            timestamp = packet.time
        
        # 检查是否有IP层
        if IP not in packet:
            return None
        
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        packet_size = len(packet)
        
        # 根据上层协议类型进行解析
        if TCP in packet:
            return self._parse_tcp_packet(packet, timestamp, source_ip, destination_ip, packet_size)
        elif UDP in packet:
            return self._parse_udp_packet(packet, timestamp, source_ip, destination_ip, packet_size)
        elif ICMP in packet:
            return self._parse_icmp_packet(packet, timestamp, source_ip, destination_ip, packet_size)
        else:
            # 其他协议
            return ParsedPacket(
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=ip_layer.proto,
                packet_size=packet_size
            )
    
    def _parse_tcp_packet(self, packet: Packet, timestamp: float, source_ip: str, 
                         destination_ip: str, packet_size: int) -> ParsedPacket:
        """解析TCP数据包"""
        tcp_layer = packet[TCP]
        
        # 提取TCP标志
        flags = []
        if tcp_layer.flags & 0x01: flags.append('F')
        if tcp_layer.flags & 0x02: flags.append('S')
        if tcp_layer.flags & 0x04: flags.append('R')
        if tcp_layer.flags & 0x08: flags.append('P')
        if tcp_layer.flags & 0x10: flags.append('A')
        if tcp_layer.flags & 0x20: flags.append('U')
        if tcp_layer.flags & 0x40: flags.append('E')
        if tcp_layer.flags & 0x80: flags.append('C')
        tcp_flags = ''.join(flags)
        
        # 计算 payload 大小
        payload_size = max(0, packet_size - (ip_layer.ihl * 4) - (tcp_layer.dataofs * 4))
        
        return ParsedPacket(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="TCP",
            source_port=tcp_layer.sport,
            destination_port=tcp_layer.dport,
            packet_size=packet_size,
            tcp_flags=tcp_flags,
            payload_size=payload_size
        )
    
    def _parse_udp_packet(self, packet: Packet, timestamp: float, source_ip: str, 
                         destination_ip: str, packet_size: int) -> ParsedPacket:
        """解析UDP数据包"""
        udp_layer = packet[UDP]
        
        # 计算 payload 大小
        payload_size = max(0, packet_size - (ip_layer.ihl * 4) - 8)
        
        return ParsedPacket(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="UDP",
            source_port=udp_layer.sport,
            destination_port=udp_layer.dport,
            packet_size=packet_size,
            payload_size=payload_size
        )
    
    def _parse_icmp_packet(self, packet: Packet, timestamp: float, source_ip: str, 
                          destination_ip: str, packet_size: int) -> ParsedPacket:
        """解析ICMP数据包"""
        icmp_layer = packet[ICMP]
        
        # 计算 payload 大小
        payload_size = max(0, packet_size - (ip_layer.ihl * 4) - 8)
        
        return ParsedPacket(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="ICMP",
            packet_size=packet_size,
            icmp_type=icmp_layer.type,
            icmp_code=icmp_layer.code,
            payload_size=payload_size
        )
    
    def get_packet_summary(self, parsed_packet: ParsedPacket) -> str:
        """获取数据包摘要信息"""
        if parsed_packet.protocol in ["TCP", "UDP"]:
            return f"{parsed_packet.timestamp:.3f} {parsed_packet.protocol} {parsed_packet.source_ip}:{parsed_packet.source_port} -> {parsed_packet.destination_ip}:{parsed_packet.destination_port} {parsed_packet.packet_size} bytes"
        elif parsed_packet.protocol == "ICMP":
            return f"{parsed_packet.timestamp:.3f} ICMP {parsed_packet.source_ip} -> {parsed_packet.destination_ip} Type:{parsed_packet.icmp_type} Code:{parsed_packet.icmp_code} {parsed_packet.packet_size} bytes"
        else:
            return f"{parsed_packet.timestamp:.3f} {parsed_packet.protocol} {parsed_packet.source_ip} -> {parsed_packet.destination_ip} {parsed_packet.packet_size} bytes"
    
    def parsed_packet_to_dict(self, parsed_packet: ParsedPacket) -> Dict[str, Any]:
        """将解析后的数据包转换为字典格式"""
        return {
            "timestamp": parsed_packet.timestamp,
            "source_ip": parsed_packet.source_ip,
            "destination_ip": parsed_packet.destination_ip,
            "protocol": parsed_packet.protocol,
            "source_port": parsed_packet.source_port,
            "destination_port": parsed_packet.destination_port,
            "packet_size": parsed_packet.packet_size,
            "icmp_type": parsed_packet.icmp_type,
            "icmp_code": parsed_packet.icmp_code,
            "tcp_flags": parsed_packet.tcp_flags,
            "payload_size": parsed_packet.payload_size
        }
