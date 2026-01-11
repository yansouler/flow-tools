from collections import defaultdict
from typing import Dict, Any, List, Optional
from receiver.packet_parser import ParsedPacket

class NATAnalyzer:
    def __init__(self):
        # NAT转换映射表：内部地址 -> 外部地址
        self.nat_mappings: Dict[str, Dict[str, str]] = defaultdict(dict)
        
        # 检测到的NAT类型
        self.nat_type: Optional[str] = None
        
        # 内部网络地址范围（用于判断是否为内部IP）
        self.internal_networks = [
            "10.",         # 10.0.0.0/8
            "172.16.",     # 172.16.0.0/12
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168."     # 192.168.0.0/16
        ]
    
    def is_internal_ip(self, ip: str) -> bool:
        """判断是否为内部IP地址"""
        return any(ip.startswith(net) for net in self.internal_networks)
    
    def analyze_packet(self, parsed_packet: ParsedPacket) -> bool:
        """分析数据包，检测NAT存在"""
        # 仅处理TCP和UDP数据包，因为ICMP没有端口信息
        if parsed_packet.protocol not in ["TCP", "UDP"]:
            return False
        
        source_ip = parsed_packet.source_ip
        destination_ip = parsed_packet.destination_ip
        source_port = parsed_packet.source_port
        destination_port = parsed_packet.destination_port
        
        # 检测NAT的基本逻辑：
        # 1. 如果源IP是内部IP，目的IP是外部IP，记录这个连接
        # 2. 当收到返回的数据包时，比较源IP是否与原始目的IP一致
        # 3. 如果不一致，则可能存在NAT
        
        # 情况1：内部主机访问外部网络
        if self.is_internal_ip(source_ip) and not self.is_internal_ip(destination_ip):
            # 创建内部端点标识
            internal_endpoint = f"{source_ip}:{source_port}"
            # 创建会话标识（使用目的IP+端口和协议）
            session_key = f"{destination_ip}:{destination_port}:{parsed_packet.protocol}"
            # 记录内部端点到会话的映射
            self.nat_mappings[session_key]["internal"] = internal_endpoint
            
        # 情况2：外部网络返回数据到内部主机
        elif not self.is_internal_ip(source_ip) and self.is_internal_ip(destination_ip):
            # 创建会话标识（使用源IP+端口和协议，因为这是返回的数据包）
            session_key = f"{source_ip}:{source_port}:{parsed_packet.protocol}"
            
            if session_key in self.nat_mappings:
                # 记录外部端点
                self.nat_mappings[session_key]["external"] = f"{source_ip}:{source_port}"
                # 记录转换后的内部端点
                self.nat_mappings[session_key]["translated_internal"] = f"{destination_ip}:{destination_port}"
                return True
        
        return False
    
    def detect_nat_presence(self) -> bool:
        """检测是否存在NAT"""
        # 如果存在任何NAT映射，则检测到NAT
        for session_key, mapping in self.nat_mappings.items():
            if "internal" in mapping and "external" in mapping:
                return True
        return False
    
    def identify_nat_type(self) -> Optional[str]:
        """识别NAT类型"""
        if not self.detect_nat_presence():
            return None
        
        # 这里实现简化的NAT类型识别
        # 实际的NAT类型识别需要更复杂的测试，通常需要外部服务器配合
        # 我们这里基于转换映射的特征进行初步判断
        
        # 统计不同内部端点到外部端点的映射关系
        internal_to_external = defaultdict(set)
        external_to_internal = defaultdict(set)
        
        for session_key, mapping in self.nat_mappings.items():
            if "internal" in mapping and "external" in mapping:
                internal = mapping["internal"]
                external = mapping["external"]
                internal_to_external[internal].add(external)
                external_to_internal[external].add(internal)
        
        # 分析映射特征
        multiple_external_per_internal = any(len(exts) > 1 for exts in internal_to_external.values())
        multiple_internal_per_external = any(len(ints) > 1 for ints in external_to_internal.values())
        
        if multiple_external_per_internal:
            # 同一个内部端点映射到多个外部端点，可能是对称NAT
            self.nat_type = "Symmetric NAT"
        elif multiple_internal_per_external:
            # 多个内部端点映射到同一个外部端点，可能是全锥形NAT
            self.nat_type = "Full Cone NAT"
        else:
            # 一对一映射，需要进一步分析
            # 这里简化处理，假设是地址限制锥形NAT
            self.nat_type = "Address Restricted Cone NAT"
        
        return self.nat_type
    
    def get_nat_mappings(self) -> Dict[str, Dict[str, str]]:
        """获取NAT转换映射表"""
        return dict(self.nat_mappings)
    
    def generate_nat_report(self) -> Dict[str, Any]:
        """生成NAT分析报告"""
        nat_present = self.detect_nat_presence()
        nat_type = self.identify_nat_type()
        mappings = self.get_nat_mappings()
        
        # 统计映射数量
        total_mappings = len(mappings)
        active_mappings = sum(1 for m in mappings.values() if "internal" in m and "external" in m)
        
        return {
            "nat_present": nat_present,
            "nat_type": nat_type,
            "total_mappings": total_mappings,
            "active_mappings": active_mappings,
            "mappings": mappings
        }
    
    def reset_analyzer(self) -> None:
        """重置NAT分析器"""
        self.nat_mappings.clear()
        self.nat_type = None
    
    def get_nat_stats(self) -> Dict[str, Any]:
        """获取NAT统计信息"""
        nat_present = self.detect_nat_presence()
        nat_type = self.identify_nat_type()
        mappings = self.get_nat_mappings()
        
        return {
            "nat_present": nat_present,
            "nat_type": nat_type,
            "mapping_count": len(mappings)
        }
