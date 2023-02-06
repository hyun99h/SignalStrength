import socket
import sys
import os
import time
from struct import *

def packet_recv(interface_name):
    try:
        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        rawSocket.bind((interface_name, 0))
        rawSocket.settimeout(0.3)
        packet = rawSocket.recvfrom(2048)[0]
        # 인터페이스 패킷 캡처
        rawSocket.close()
        return packet
    except:
        return None
# 패킷 받기

def radiotap_check(packet):
    radiotap_header = Struct("!2cHI")
    version, pad, length, present = radiotap_header.unpack_from(packet)
    length = length >> 8
    if length == 0:
        return None, None
    
    present = unpack(">I", pack("<I", present))[0] # Big -> Little
    if present & 0b100000 == 0:
        return None, None
    # dbm antenna check

    skip_fields = 0

    if present & 0b1:
        skip_fields += 8 # TSFT
    if present & 0b10:
        skip_fields += 1 # Flags
    if present & 0b100:
        skip_fields += 1 # Rate
    if present & 0b1000:
        skip_fields += 4 # Channel
    if present & 0b10000:
        skip_fields += 1 # FHSS

    present_add_count = 0
    present_add = present
    while 1:
        if present_add & (0b1000 << 28) != 0:
            size = radiotap_header.size + present_add_count * 4
            present_add = unpack("<I", packet[size : size + 4])[0]
            present_add_count += 1
            continue
        break
    # 추가 present의 유무 확인

    sig_idx = radiotap_header.size + present_add_count * 4 + skip_fields
    signal_strength = unpack("b", packet[sig_idx : sig_idx + 1])[0]
    # 신호 세기 확인

    return packet[length:], signal_strength
# radiotap header, 신호 세기 받기


def dot11_check(packet, mac):
    dot11_frame = Struct("!HH6s6s6s")
    if len(packet) < dot11_frame.size:
        return None

    control, duration, addr1, addr2, addr3 = dot11_frame.unpack_from(packet)
    if mac == addr2:
        ta_mac = ':'.join(f'{x:02x}' for x in addr2)
        return ta_mac.upper()
    else:
        return None
# 802.11 frame data. 




if len(sys.argv) != 3:
    print("syntax : sudo python3 signal-strength.py <interface> <mac>")
    sys.exit()

interface_name = sys.argv[1]

mac = bytes()
for b in sys.argv[2].split(":"):
    mac += pack("B", int(b, 16))

channel = 1
os.system("iwconfig " + interface_name + " channel " + str(channel))

channel_hop_flag = 0

while 1:
    time.sleep(0.01)
    if channel_hop_flag == 0:
        channel = (channel + 5) % 14
        if channel == 0 :
            channel += 1
        os.system("iwconfig " + interface_name + " channel " + str(channel))
        print("\rChannel: %3s " % str(channel), end='')

    packet = packet_recv(interface_name)
    if packet is None:
        continue

    packet_wo_rh, antenna = radiotap_check(packet)
    if packet_wo_rh is None:
        continue

    ta_mac = dot11_check(packet_wo_rh, mac)
    if ta_mac is None:
        continue
    
    if channel_hop_flag == 0:
        channel_hop_flag = 1
        print()

    print("\rSignal Strength: %3s " % str(antenna * -1), end='')
