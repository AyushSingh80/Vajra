# #scanner/ports.py
# import socket
# from scapy.all import IP, TCP, sr1

# def tcp_connect_scan(ip, port, timeout=1):
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             s.settimeout(timeout)
#             result = s.connect_ex((ip, port))
#             if result == 0:
#                 return "open"
#             else:
#                 return "closed"
#     except Exception:
#         return "filtered"
# def syn_scan(ip, port):
#     pkt = IP(dst=ip)/TCP(dport=port, flags="S")
#     response = sr1(pkt, timeout=2, verbose=0)
#     if response and response.haslayer(TCP):
#         if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
#             return "open"
#         elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
#             return "closed"
#     return "filtered"
