import socket
import struct
import time
import os

ICMP_ECHO_REQUEST = 8
ICMP_CODE = 0


def calculate_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i + 1] << 8) + data[i]
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    return ~checksum & 0xffff


def build_packet(pid, seq):
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, ICMP_CODE, 0, pid, seq)
    payload = b'NetworkDiagnostics'
    chksum = calculate_checksum(header + payload)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, ICMP_CODE, chksum, pid, seq)
    return header + payload


def extract_icmp_info(packet):
    ip_hdr = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    ttl = ip_hdr[5]
    icmp_hdr = struct.unpack('!BBHHh', packet[20:28])
    return ttl, icmp_hdr[0], icmp_hdr[1], icmp_hdr[3], icmp_hdr[4]


def run_icmp_test(target_host, max_hops=30, timeout=2):
    print(f"\nICMP Diagnostics to {target_host}, max {max_hops} hops")
    try:
        dest_ip = socket.gethostbyname(target_host)
        pid = os.getpid() & 0xFFFF
        sent, received = 0, 0

        for ttl in range(1, max_hops + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                s.settimeout(timeout)

                packet = build_packet(pid, ttl)
                sent += 1
                try:
                    start = time.time()
                    s.sendto(packet, (dest_ip, 0))
                    reply, addr = s.recvfrom(1024)
                    rtt = (time.time() - start) * 1000

                    ttl_val, icmp_type, code, _, _ = extract_icmp_info(reply)
                    if icmp_type == 0:
                        print(f"{ttl}: Reply from {addr[0]} in {rtt:.2f}ms — Destination reached.")
                        received += 1
                        break
                    elif icmp_type == 11:
                        print(f"{ttl}: Hop {addr[0]} (TTL Expired) in {rtt:.2f}ms")
                        received += 1
                    elif icmp_type == 3:
                        print(f"{ttl}: Destination Unreachable from {addr[0]} — Possibly blocked")
                    else:
                        print(f"{ttl}: ICMP Type {icmp_type} from {addr[0]}")
                except socket.timeout:
                    print(f"{ttl}: * Request timed out")

        loss = ((sent - received) / sent) * 100 if sent else 0
        print(f"\nPacket Loss: {loss:.2f}% ({sent - received} lost of {sent})")
        if received == 0:
            print("⚠️  No replies received — firewall or ICMP blocking suspected.")

    except Exception as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    user_input = input("Enter target host (e.g., 8.8.8.8): ")
    run_icmp_test(user_input)
