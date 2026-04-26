"""生成PCAP测试文件用于AI流量分析测试"""
from scapy.all import IP, TCP, Raw, wrpcap
import os

def create_http_packet(src_ip, dst_ip, method, uri, host, user_agent, payload=None, dst_port=80):
    """创建HTTP数据包"""
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=dst_port, flags='PA') / Raw(load=f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n")
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt

# 生成正常流量PCAP文件
normal_packets = [
    create_http_packet("192.168.1.100", "192.168.1.1", "GET", "/index.html", "www.example.com", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    create_http_packet("192.168.1.100", "192.168.1.1", "GET", "/style.css", "www.example.com", "Mozilla/5.0"),
    create_http_packet("192.168.1.100", "192.168.1.1", "GET", "/script.js", "www.example.com", "Mozilla/5.0"),
    create_http_packet("192.168.1.100", "192.168.1.1", "POST", "/api/login", "www.example.com", "Mozilla/5.0", "username=test&password=123456"),
]
wrpcap("e:/AI_Network_Sentinel/data/raw_captures/test_normal.pcap", normal_packets)
print("[OK] test_normal.pcap (normal traffic)")

# 生成SQL注入攻击PCAP文件
sqli_packets = [
    create_http_packet("192.168.1.100", "192.168.1.1", "GET", "/login?username=admin' OR '1'='1&password=123456", "192.168.1.100", "sqlmap/1.6.3#stable"),
    create_http_packet("192.168.1.100", "192.168.1.1", "POST", "/search", "192.168.1.100", "Mozilla/5.0", "id=1 UNION SELECT * FROM users--"),
    create_http_packet("192.168.1.100", "192.168.1.1", "GET", "/admin?id=1' DROP TABLE users--", "192.168.1.100", "python-requests/2.28.0"),
]
wrpcap("e:/AI_Network_Sentinel/data/raw_captures/test_sqli.pcap", sqli_packets)
print("[OK] test_sqli.pcap (SQL injection attack)")

# 生成XSS攻击PCAP文件
xss_packets = [
    create_http_packet("192.168.1.100", "192.168.1.1", "POST", "/comment", "192.168.1.100", "Mozilla/5.0", "<script>alert('XSS')</script>"),
    create_http_packet("192.168.1.100", "192.168.1.1", "GET", "/search?q=<img src=x onerror=alert('XSS')>", "192.168.1.100", "python-requests/2.28.0"),
    create_http_packet("192.168.1.100", "192.168.1.1", "POST", "/profile", "192.168.1.100", "Mozilla/5.0", "<script>document.cookie</script>"),
]
wrpcap("e:/AI_Network_Sentinel/data/raw_captures/test_xss.pcap", xss_packets)
print("[OK] test_xss.pcap (XSS attack)")

# 生成混合攻击PCAP文件
mixed_packets = [
    create_http_packet("192.168.1.100", "192.168.1.1", "POST", "/admin/login", "192.168.1.100", "sqlmap/1.6.3#stable", "username=admin' OR '1'='1&password=admin"),
    create_http_packet("192.168.1.100", "192.168.1.1", "GET", "/profile?name=<script>alert('XSS')</script>", "192.168.1.100", "Mozilla/5.0"),
    create_http_packet("192.168.1.100", "192.168.1.1", "POST", "/update", "192.168.1.100", "python-requests/2.28.0", "data=<script>alert('XSS')</script>&id=1' OR 1=1--"),
]
wrpcap("e:/AI_Network_Sentinel/data/raw_captures/test_mixed.pcap", mixed_packets)
print("[OK] test_mixed.pcap (mixed attack)")

print("\nAll PCAP test files generated!")
