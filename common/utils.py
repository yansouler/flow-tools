import os
import csv
import random
from typing import List, Tuple

from common.config import IPConfig

def validate_ip(ip: str) -> bool:
    """验证IP地址格式"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

def generate_random_ip() -> str:
    """生成随机IP地址"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_random_port() -> int:
    """生成随机端口号"""
    return random.randint(1024, 65535)

def load_ip_list(file_path: str) -> List[IPConfig]:
    """从文件加载IP配置列表"""
    ip_list = []
    
    if not os.path.exists(file_path):
        return ip_list
    
    _, ext = os.path.splitext(file_path)
    
    if ext.lower() == '.csv':
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip_config = IPConfig(
                    source_ip=row.get('source_ip', ''),
                    destination_ip=row.get('destination_ip', ''),
                    protocol=row.get('protocol', 'TCP').upper(),
                    source_port=int(row.get('source_port', 0)) if row.get('source_port') else 0,
                    destination_port=int(row.get('destination_port', 0)) if row.get('destination_port') else 0
                )
                ip_list.append(ip_config)
    
    elif ext.lower() == '.json':
        import json
        with open(file_path, 'r') as f:
            data = json.load(f)
            for item in data:
                ip_config = IPConfig(
                    source_ip=item.get('source_ip', ''),
                    destination_ip=item.get('destination_ip', ''),
                    protocol=item.get('protocol', 'TCP').upper(),
                    source_port=int(item.get('source_port', 0)) if item.get('source_port') else 0,
                    destination_port=int(item.get('destination_port', 0)) if item.get('destination_port') else 0
                )
                ip_list.append(ip_config)
    
    return ip_list

def save_ip_list(ip_list: List[IPConfig], file_path: str) -> None:
    """保存IP配置列表到文件"""
    _, ext = os.path.splitext(file_path)
    
    if ext.lower() == '.csv':
        with open(file_path, 'w', newline='') as f:
            fieldnames = ['source_ip', 'destination_ip', 'protocol', 'source_port', 'destination_port']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ip_config in ip_list:
                writer.writerow({
                    'source_ip': ip_config.source_ip,
                    'destination_ip': ip_config.destination_ip,
                    'protocol': ip_config.protocol,
                    'source_port': ip_config.source_port,
                    'destination_port': ip_config.destination_port
                })
    
    elif ext.lower() == '.json':
        import json
        data = []
        for ip_config in ip_list:
            data.append({
                'source_ip': ip_config.source_ip,
                'destination_ip': ip_config.destination_ip,
                'protocol': ip_config.protocol,
                'source_port': ip_config.source_port,
                'destination_port': ip_config.destination_port
            })
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)

def calculate_checksum(data: bytes) -> int:
    """计算校验和"""
    if len(data) % 2 != 0:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)
    
    return ~checksum & 0xffff
