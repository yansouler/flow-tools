import subprocess
import platform
from typing import List, Dict, Any

class InterfaceManager:
    def __init__(self):
        self.created_interfaces: List[str] = []
        self.os_type = platform.system()
    
    def create_loopback_interfaces(self, count: int, base_ip: str = "192.168.1.") -> List[str]:
        """创建多个Loopback接口"""
        if self.os_type != "Windows":
            raise NotImplementedError("Loopback interface management is only supported on Windows")
        
        created_ifs = []
        for i in range(count):
            interface_name = f"Loopback_{i+1}"
            ip_address = f"{base_ip}{100+i}"
            
            if self._create_single_loopback(interface_name, ip_address):
                created_ifs.append(interface_name)
                self.created_interfaces.append(interface_name)
        
        return created_ifs
    
    def _create_single_loopback(self, name: str, ip_address: str) -> bool:
        """创建单个Loopback接口"""
        try:
            # 在Windows上，我们可以使用netsh命令来管理Loopback接口
            # 注意：这需要管理员权限
            
            # 创建Loopback适配器
            # 这里使用devcon命令，需要先安装Windows Driver Kit
            # 或者使用PowerShell命令New-NetAdapter
            cmd = f"powershell -Command New-NetAdapter -Name '{name}' -InterfaceDescription 'Loopback Adapter for Traffic Test' -Type Loopback"
            subprocess.run(cmd, shell=True, check=True)
            
            # 配置IP地址和子网掩码
            cmd = f"netsh interface ip set address name='{name}' static {ip_address} 255.255.255.255"
            subprocess.run(cmd, shell=True, check=True)
            
            # 启用接口
            cmd = f"netsh interface set interface '{name}' admin=enabled"
            subprocess.run(cmd, shell=True, check=True)
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to create loopback interface {name}: {e}")
            return False
    
    def delete_loopback_interfaces(self, interfaces: List[str] = None) -> bool:
        """删除Loopback接口"""
        if self.os_type != "Windows":
            raise NotImplementedError("Loopback interface management is only supported on Windows")
        
        if interfaces is None:
            interfaces = self.created_interfaces.copy()
        
        success = True
        for interface in interfaces:
            if self._delete_single_loopback(interface):
                if interface in self.created_interfaces:
                    self.created_interfaces.remove(interface)
            else:
                success = False
        
        return success
    
    def _delete_single_loopback(self, name: str) -> bool:
        """删除单个Loopback接口"""
        try:
            # 禁用接口
            cmd = f"netsh interface set interface '{name}' admin=disabled"
            subprocess.run(cmd, shell=True, check=True)
            
            # 删除接口
            cmd = f"powershell -Command Remove-NetAdapter -Name '{name}' -Confirm:$false"
            subprocess.run(cmd, shell=True, check=True)
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to delete loopback interface {name}: {e}")
            return False
    
    def configure_interface_ip(self, interface_name: str, ip_address: str, subnet_mask: str = "255.255.255.255") -> bool:
        """配置接口IP地址"""
        if self.os_type != "Windows":
            raise NotImplementedError("Interface configuration is only supported on Windows")
        
        try:
            cmd = f"netsh interface ip set address name='{interface_name}' static {ip_address} {subnet_mask}"
            subprocess.run(cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to configure IP for interface {interface_name}: {e}")
            return False
    
    def list_interfaces(self) -> List[Dict[str, Any]]:
        """列出所有网络接口"""
        if self.os_type != "Windows":
            raise NotImplementedError("Interface listing is only supported on Windows")
        
        interfaces = []
        try:
            # 使用ipconfig命令获取接口信息
            cmd = "ipconfig /all"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # 解析输出，提取接口信息
            # 这里只是一个简单的示例，实际解析需要更复杂的逻辑
            lines = result.stdout.splitlines()
            current_interface = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith("Ethernet adapter") or line.startswith("Wireless LAN adapter"):
                    if current_interface:
                        interfaces.append(current_interface)
                        current_interface = {}
                    current_interface["name"] = line.split(":")[0].split("adapter")[1].strip()
                elif ":" in line:
                    key, value = line.split(":", 1)
                    current_interface[key.strip()] = value.strip()
            
            if current_interface:
                interfaces.append(current_interface)
                
        except Exception as e:
            print(f"Failed to list interfaces: {e}")
        
        return interfaces
    
    def cleanup(self) -> bool:
        """清理所有创建的接口"""
        return self.delete_loopback_interfaces()
    
    def __del__(self):
        """析构函数，自动清理"""
        self.cleanup()
