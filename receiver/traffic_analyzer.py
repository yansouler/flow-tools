import time
from collections import defaultdict, Counter
from typing import Dict, Any, List, Optional
from receiver.packet_parser import ParsedPacket

class TrafficAnalyzer:
    def __init__(self):
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        
        # 按协议统计
        self.protocol_stats = defaultdict(lambda: {
            "count": 0,
            "bytes": 0
        })
        
        # 按源IP统计
        self.source_ip_stats = defaultdict(lambda: {
            "count": 0,
            "bytes": 0
        })
        
        # 按目的IP统计
        self.destination_ip_stats = defaultdict(lambda: {
            "count": 0,
            "bytes": 0
        })
        
        # 按源IP+端口统计
        self.source_endpoint_stats = defaultdict(lambda: {
            "count": 0,
            "bytes": 0
        })
        
        # 按目的IP+端口统计
        self.destination_endpoint_stats = defaultdict(lambda: {
            "count": 0,
            "bytes": 0
        })
        
        # 流量时间分布（每秒统计）
        self.time_distribution = defaultdict(lambda: {
            "count": 0,
            "bytes": 0
        })
        
        # TCP标志统计
        self.tcp_flags_stats = Counter()
        
        # ICMP类型统计
        self.icmp_type_stats = Counter()
    
    def add_parsed_packet(self, parsed_packet: ParsedPacket) -> None:
        """添加解析后的数据包进行统计"""
        self.total_packets += 1
        self.total_bytes += parsed_packet.packet_size
        
        # 按协议统计
        self.protocol_stats[parsed_packet.protocol]["count"] += 1
        self.protocol_stats[parsed_packet.protocol]["bytes"] += parsed_packet.packet_size
        
        # 按源IP统计
        self.source_ip_stats[parsed_packet.source_ip]["count"] += 1
        self.source_ip_stats[parsed_packet.source_ip]["bytes"] += parsed_packet.packet_size
        
        # 按目的IP统计
        self.destination_ip_stats[parsed_packet.destination_ip]["count"] += 1
        self.destination_ip_stats[parsed_packet.destination_ip]["bytes"] += parsed_packet.packet_size
        
        # 按源IP+端口统计
        source_endpoint = f"{parsed_packet.source_ip}:{parsed_packet.source_port}"
        self.source_endpoint_stats[source_endpoint]["count"] += 1
        self.source_endpoint_stats[source_endpoint]["bytes"] += parsed_packet.packet_size
        
        # 按目的IP+端口统计
        destination_endpoint = f"{parsed_packet.destination_ip}:{parsed_packet.destination_port}"
        self.destination_endpoint_stats[destination_endpoint]["count"] += 1
        self.destination_endpoint_stats[destination_endpoint]["bytes"] += parsed_packet.packet_size
        
        # 流量时间分布
        time_key = int(parsed_packet.timestamp)
        self.time_distribution[time_key]["count"] += 1
        self.time_distribution[time_key]["bytes"] += parsed_packet.packet_size
        
        # TCP标志统计
        if parsed_packet.protocol == "TCP" and parsed_packet.tcp_flags:
            self.tcp_flags_stats[parsed_packet.tcp_flags] += 1
        
        # ICMP类型统计
        if parsed_packet.protocol == "ICMP":
            icmp_type = f"Type{parsed_packet.icmp_type}_Code{parsed_packet.icmp_code}"
            self.icmp_type_stats[icmp_type] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        elapsed_time = time.time() - self.start_time
        
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "elapsed_time": elapsed_time,
            "packet_rate": self.total_packets / elapsed_time if elapsed_time > 0 else 0,
            "bit_rate": (self.total_bytes * 8) / elapsed_time if elapsed_time > 0 else 0,
            "protocol_stats": dict(self.protocol_stats),
            "source_ip_stats": dict(self.source_ip_stats),
            "destination_ip_stats": dict(self.destination_ip_stats),
            "source_endpoint_stats": dict(self.source_endpoint_stats),
            "destination_endpoint_stats": dict(self.destination_endpoint_stats),
            "time_distribution": dict(self.time_distribution),
            "tcp_flags_stats": dict(self.tcp_flags_stats),
            "icmp_type_stats": dict(self.icmp_type_stats)
        }
    
    def generate_report(self, filename: Optional[str] = None) -> Dict[str, Any]:
        """生成分析报告"""
        stats = self.get_stats()
        
        # 生成报告内容
        report = {
            "summary": {
                "start_time": self.start_time,
                "end_time": time.time(),
                "elapsed_time": stats["elapsed_time"],
                "total_packets": stats["total_packets"],
                "total_bytes": stats["total_bytes"],
                "packet_rate": stats["packet_rate"],
                "bit_rate": stats["bit_rate"]
            },
            "protocol_breakdown": stats["protocol_stats"],
            "top_source_ips": self._get_top_entries(stats["source_ip_stats"], 10),
            "top_destination_ips": self._get_top_entries(stats["destination_ip_stats"], 10),
            "top_source_endpoints": self._get_top_entries(stats["source_endpoint_stats"], 10),
            "top_destination_endpoints": self._get_top_entries(stats["destination_endpoint_stats"], 10),
            "tcp_flags_distribution": stats["tcp_flags_stats"],
            "icmp_type_distribution": stats["icmp_type_stats"],
            "time_series": stats["time_distribution"]
        }
        
        # 如果指定了文件名，将报告保存到文件
        if filename:
            import json
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
        
        return report
    
    def _get_top_entries(self, stats_dict: Dict[str, Dict[str, int]], limit: int = 10) -> List[Dict[str, Any]]:
        """获取统计数据中排名靠前的条目"""
        # 按数据包数量排序
        sorted_entries = sorted(
            stats_dict.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )[:limit]
        
        # 转换格式
        top_entries = []
        for entry, stats in sorted_entries:
            top_entries.append({
                "entry": entry,
                "count": stats["count"],
                "bytes": stats["bytes"]
            })
        
        return top_entries
    
    def reset_stats(self) -> None:
        """重置统计信息"""
        self.__init__()
    
    def get_protocol_distribution(self) -> Dict[str, float]:
        """获取协议分布百分比"""
        if self.total_packets == 0:
            return {}
        
        distribution = {}
        for protocol, stats in self.protocol_stats.items():
            distribution[protocol] = (stats["count"] / self.total_packets) * 100
        
        return distribution
    
    def get_time_series_data(self) -> Dict[str, List[Any]]:
        """获取时间序列数据，用于可视化"""
        # 按时间排序
        sorted_time = sorted(self.time_distribution.keys())
        
        timestamps = []
        packet_counts = []
        byte_counts = []
        
        for t in sorted_time:
            timestamps.append(t)
            packet_counts.append(self.time_distribution[t]["count"])
            byte_counts.append(self.time_distribution[t]["bytes"])
        
        return {
            "timestamps": timestamps,
            "packet_counts": packet_counts,
            "byte_counts": byte_counts
        }
