from scapy.all import rdpcap, IP, UDP
from collections import defaultdict

PCAP_FILE = "file"
DEST_IP = "dest_ip"


def check_ts_continuity_with_time(pcap_file, dest_ip):
    packets = rdpcap(pcap_file)
    pid_counters = defaultdict(lambda: None)
    discontinuities = []
    total_ts_packets = 0
    pkt_index = 1

    first_ts = None
    last_ts = None

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            continue

        if pkt[IP].dst != dest_ip:
            continue

        if first_ts is None:
            first_ts = pkt.time
        last_ts = pkt.time

        payload = bytes(pkt[UDP].payload)
        for offset in range(0, len(payload), 188):
            ts_packet = payload[offset:offset+188]
            if len(ts_packet) < 188 or ts_packet[0] != 0x47:
                continue  # não é TS válido

            total_ts_packets += 1

            pid = ((ts_packet[1] & 0x1F) << 8) | ts_packet[2]
            cc = ts_packet[3] & 0x0F

            last_cc = pid_counters[pid]
            if last_cc is not None and ((last_cc + 1) % 16) != cc:
                discontinuities.append({
                    "packet": pkt_index,
                    "pid": pid,
                    "expected": (last_cc + 1) % 16,
                    "found": cc,
                    "timestamp": pkt.time - first_ts  # tempo relativo
                })

            pid_counters[pid] = cc
        pkt_index += 1

    duration = last_ts - first_ts if first_ts and last_ts else 0
    return discontinuities, total_ts_packets, duration

# Executar
discontinuities, total, duration = check_ts_continuity_with_time(PCAP_FILE, DEST_IP)

if not discontinuities:
    print("✅ Todos os pacotes MPEG-TS estão em ordem!")
else:
    print(f"⚠️ Foram encontradas {len(discontinuities)} descontinuidades:")
    for d in discontinuities:
        print(f"  - Pacote {d['packet']} ({d['timestamp']:.3f}s): PID {d['pid']} - esperado CC {d['expected']}, encontrado {d['found']}")

print(f"\n📦 Foram encontradas {len(discontinuities)} descontinuidades em um total de {total} pacotes MPEG-TS analisados.")
print(f"🕒 Duração total da captura: {duration:.3f} segundos.")
