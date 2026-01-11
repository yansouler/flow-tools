import json
import struct
from enum import Enum
from typing import Dict, Any, Optional

class MessageType(Enum):
    """消息类型枚举"""
    # 控制消息
    HELLO = 0x01          # 握手消息
    ACK = 0x02            # 确认消息
    ERROR = 0x03          # 错误消息
    
    # 配置消息
    CONFIG_REQUEST = 0x10  # 配置请求
    CONFIG_RESPONSE = 0x11 # 配置响应
    
    # 状态消息
    STATUS_UPDATE = 0x20   # 状态更新
    STATISTICS = 0x21      # 统计信息
    
    # 测试控制消息
    TEST_START = 0x30      # 开始测试
    TEST_STOP = 0x31       # 停止测试
    TEST_RESULT = 0x32     # 测试结果

class Message:
    """通信消息类"""
    def __init__(self, msg_type: MessageType, payload: Dict[str, Any] = None):
        self.msg_type = msg_type
        self.payload = payload or {}
    
    def serialize(self) -> bytes:
        """序列化消息为二进制格式"""
        # 将payload转换为JSON字符串
        payload_json = json.dumps(self.payload)
        payload_bytes = payload_json.encode('utf-8')
        
        # 构造消息头
        # 消息头格式：
        # - 2字节：魔数（0xCAFE）
        # - 1字节：消息类型
        # - 4字节：payload长度
        magic = struct.pack('!H', 0xCAFE)
        msg_type = struct.pack('!B', self.msg_type.value)
        payload_len = struct.pack('!I', len(payload_bytes))
        
        # 组合消息
        message = magic + msg_type + payload_len + payload_bytes
        
        return message
    
    @classmethod
    def deserialize(cls, data: bytes) -> Optional['Message']:
        """从二进制数据反序列化消息"""
        # 检查数据长度
        if len(data) < 7:  # 消息头长度为7字节
            return None
        
        # 解析消息头
        magic = struct.unpack('!H', data[0:2])[0]
        msg_type_value = struct.unpack('!B', data[2:3])[0]
        payload_len = struct.unpack('!I', data[3:7])[0]
        
        # 检查魔数
        if magic != 0xCAFE:
            return None
        
        # 检查数据长度是否足够
        if len(data) < 7 + payload_len:
            return None
        
        # 解析payload
        payload_bytes = data[7:7+payload_len]
        try:
            payload = json.loads(payload_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            return None
        
        # 检查消息类型是否有效
        try:
            msg_type = MessageType(msg_type_value)
        except ValueError:
            return None
        
        return cls(msg_type, payload)
    
    def __str__(self) -> str:
        return f"Message(type={self.msg_type.name}, payload={self.payload})"

class CommunicationClient:
    """通信客户端基类"""
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None
    
    def connect(self) -> bool:
        """建立连接"""
        raise NotImplementedError("connect method must be implemented by subclass")
    
    def disconnect(self) -> None:
        """断开连接"""
        raise NotImplementedError("disconnect method must be implemented by subclass")
    
    def send_message(self, message: Message) -> bool:
        """发送消息"""
        raise NotImplementedError("send_message method must be implemented by subclass")
    
    def receive_message(self) -> Optional[Message]:
        """接收消息"""
        raise NotImplementedError("receive_message method must be implemented by subclass")

class CommunicationServer:
    """通信服务器基类"""
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server_socket = None
    
    def start(self) -> bool:
        """启动服务器"""
        raise NotImplementedError("start method must be implemented by subclass")
    
    def stop(self) -> None:
        """停止服务器"""
        raise NotImplementedError("stop method must be implemented by subclass")
    
    def accept_connection(self) -> Optional[CommunicationClient]:
        """接受客户端连接"""
        raise NotImplementedError("accept_connection method must be implemented by subclass")

# TCP实现
import socket
import threading

class TCPCommunicationClient(CommunicationClient):
    """TCP通信客户端"""
    def connect(self) -> bool:
        """建立TCP连接"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            self.socket = None
            return False
    
    def disconnect(self) -> None:
        """断开TCP连接"""
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                print(f"Error closing socket: {e}")
            finally:
                self.socket = None
    
    def send_message(self, message: Message) -> bool:
        """发送TCP消息"""
        if not self.socket:
            return False
        
        try:
            serialized = message.serialize()
            # 发送完整消息
            total_sent = 0
            while total_sent < len(serialized):
                sent = self.socket.send(serialized[total_sent:])
                if sent == 0:
                    raise RuntimeError("Socket connection broken")
                total_sent += sent
            return True
        except Exception as e:
            print(f"Failed to send message: {e}")
            self.disconnect()
            return False
    
    def receive_message(self) -> Optional[Message]:
        """接收TCP消息"""
        if not self.socket:
            return None
        
        try:
            # 接收消息头
            header = self._receive_all(7)
            if not header:
                return None
            
            # 解析消息头获取payload长度
            payload_len = struct.unpack('!I', header[3:7])[0]
            
            # 接收payload
            payload = self._receive_all(payload_len)
            if not payload:
                return None
            
            # 组合完整消息
            full_message = header + payload
            
            # 反序列化消息
            return Message.deserialize(full_message)
        except Exception as e:
            print(f"Failed to receive message: {e}")
            self.disconnect()
            return None
    
    def _receive_all(self, size: int) -> Optional[bytes]:
        """接收指定大小的数据"""
        data = b''
        while len(data) < size:
            packet = self.socket.recv(size - len(data))
            if not packet:
                return None
            data += packet
        return data

class TCPCommunicationServer(CommunicationServer):
    """TCP通信服务器"""
    def __init__(self, host: str, port: int):
        super().__init__(host, port)
        self.is_running = False
        self.thread = None
    
    def start(self) -> bool:
        """启动TCP服务器"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.is_running = True
            
            # 创建并启动服务器线程
            self.thread = threading.Thread(target=self._server_worker)
            self.thread.daemon = True
            self.thread.start()
            
            return True
        except Exception as e:
            print(f"Failed to start server: {e}")
            self.server_socket = None
            return False
    
    def stop(self) -> None:
        """停止TCP服务器"""
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                print(f"Error closing server socket: {e}")
            finally:
                self.server_socket = None
        
        if self.thread:
            self.thread.join(timeout=2.0)
    
    def _server_worker(self) -> None:
        """服务器工作线程"""
        while self.is_running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, client_address = self.server_socket.accept()
                # 这里可以处理客户端连接，例如创建客户端处理线程
                print(f"New connection from {client_address}")
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    print(f"Server error: {e}")
                break
    
    def accept_connection(self) -> Optional[TCPCommunicationClient]:
        """接受TCP连接"""
        if not self.server_socket:
            return None
        
        try:
            client_socket, client_address = self.server_socket.accept()
            client = TCPCommunicationClient(self.host, self.port)
            client.socket = client_socket
            return client
        except Exception as e:
            print(f"Failed to accept connection: {e}")
            return None
