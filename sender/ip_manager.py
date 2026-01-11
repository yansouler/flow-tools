from typing import List, Optional
from common.config import IPConfig
from common.utils import load_ip_list, save_ip_list, validate_ip

class IPManager:
    def __init__(self):
        self.ip_list: List[IPConfig] = []
    
    def load_from_file(self, file_path: str) -> List[IPConfig]:
        """从文件加载IP列表"""
        self.ip_list = load_ip_list(file_path)
        # 验证IP配置
        valid_list = []
        for ip_config in self.ip_list:
            if self._validate_ip_config(ip_config):
                valid_list.append(ip_config)
        self.ip_list = valid_list
        return self.ip_list
    
    def save_to_file(self, file_path: str) -> None:
        """保存IP列表到文件"""
        save_ip_list(self.ip_list, file_path)
    
    def add_ip_config(self, ip_config: IPConfig) -> bool:
        """添加IP配置"""
        if self._validate_ip_config(ip_config):
            self.ip_list.append(ip_config)
            return True
        return False
    
    def remove_ip_config(self, index: int) -> bool:
        """移除IP配置"""
        if 0 <= index < len(self.ip_list):
            del self.ip_list[index]
            return True
        return False
    
    def get_ip_list(self) -> List[IPConfig]:
        """获取IP列表"""
        return self.ip_list
    
    def clear_ip_list(self) -> None:
        """清空IP列表"""
        self.ip_list.clear()
    
    def _validate_ip_config(self, ip_config: IPConfig) -> bool:
        """验证IP配置有效性"""
        # 验证IP地址格式
        if not validate_ip(ip_config.source_ip):
            return False
        if not validate_ip(ip_config.destination_ip):
            return False
        
        # 验证协议类型
        if ip_config.protocol not in ["TCP", "UDP", "ICMP"]:
            return False
        
        # 验证端口范围
        if ip_config.source_port < 0 or ip_config.source_port > 65535:
            return False
        if ip_config.destination_port < 0 or ip_config.destination_port > 65535:
            return False
        
        return True
    
    def generate_random_ip_list(self, count: int, protocols: List[str] = None) -> List[IPConfig]:
        """生成随机IP列表"""
        from common.utils import generate_random_ip, generate_random_port
        
        if protocols is None:
            protocols = ["TCP", "UDP", "ICMP"]
        
        self.ip_list.clear()
        for _ in range(count):
            protocol = protocols[_ % len(protocols)]
            ip_config = IPConfig(
                source_ip=generate_random_ip(),
                destination_ip=generate_random_ip(),
                protocol=protocol,
                source_port=generate_random_port(),
                destination_port=generate_random_port() if protocol in ["TCP", "UDP"] else 0
            )
            self.ip_list.append(ip_config)
        
        return self.ip_list
