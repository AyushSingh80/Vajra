# # scanner/packet_builder.py
# from scapy.all import IP, TCP, send, sr1

# def send_syn(host, port):
#     pkt = IP(dst=host) / TCP(dport=port, flags='S')
#     resp = sr1(pkt, timeout=2, verbose=0)
#     if resp is None:
#         return 'filtered'
#     elif resp.haslayer(TCP):
#         if resp[TCP].flags == 'SA':
#             return 'open'
#         elif resp[TCP].flags == 'RA':
#             return 'closed'
#     return 'filtered'
