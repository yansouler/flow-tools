import os
import json
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class SenderConfig:
    ip_list_path: str = ""
    loopback_count: int = 1
    traffic_rate: int = 1000  # 每秒数据包数
    packet_size: int = 64  # 字节
    duration: int = 60  # 秒
    protocols: List[str] = None
    gateway: str = "127.0.0.1"
    
    def __post_init__(self):
        if self.protocols is None:
            self.protocols = ["TCP", "UDP", "ICMP"]

@dataclass
class ReceiverConfig:
    capture_interface: str = ""
    filter_rule: str = ""
    save_path: str = ""
    gateway: str = "127.0.0.1"

@dataclass
class IPConfig:
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int = 0
    destination_port: int = 0

def load_config(config_path: str) -> Dict[str, Any]:
    """加载配置文件"""
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    return {}

def save_config(config: Dict[str, Any], config_path: str) -> None:
    """保存配置文件"""
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)
