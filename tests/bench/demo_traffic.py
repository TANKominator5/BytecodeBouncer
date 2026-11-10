"""Synthetic illustration, only usable inside demo.sh's private netns.

sudo nsenter --net=/run/netns/trafficcop-demo python3 tests/bench/demo_traffic.py
"""
import fcntl
import ipaddress
import socket
import struct
import time

def mac(name):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        return fcntl.ioctl(s.fileno(),0x8927,struct.pack('256s',name.encode()))[18:24]

s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('players',0))
ethernet=mac('eth0')+mac('players')+b'\x08\x00'

def frame(src,port,proto=17):
    h=bytearray(20);h[0]=0x45;h[9]=proto
    h[12:16]=ipaddress.ip_address(src).packed;h[16:20]=ipaddress.ip_address('10.0.0.1').packed
    payload=struct.pack('!HHHH',40000,port,0,0) if proto==17 else bytes([8])+bytes(7)
    return ethernet+h+payload

for tick in range(12):
    for i in range(100):s.send(frame('10.0.0.21',7777))
    for i in range(20):s.send(frame('10.13.37.4',6010))
    for i in range(5):s.send(frame('10.0.0.66',6010))
    for i in range(8):s.send(frame('10.0.0.42',0,1))
    time.sleep(.15)
s.close()
print('Sent synthetic demo frames; dashboard values are actual XDP counters.')
