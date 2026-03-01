# sniffer.py (ПОЛНАЯ УНИВЕРСАЛЬНАЯ ВЕРСИЯ)

from collections import deque
import threading
from datetime import datetime
from typing import List, Optional

from config import BPF_FILTER
from data_structures import PacketData

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
except ImportError:
    print("[SNIFFER] Ошибка: Scapy не найдена.")
    raise


class PacketSniffer:
    def __init__(self):
        # MAX_BUFFER_SIZE теперь не импортируется, но можно его задать здесь
        self.buffer = deque(maxlen=10000)
        self.lock = threading.Lock()
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.iface_to_use: Optional[str] = None
        self.bpf_filter: str = BPF_FILTER
        self.dns_cache = {}

    def set_config(self, iface_name: str, bpf_filter: str):
        self.iface_to_use = iface_name
        self.bpf_filter = bpf_filter

    def start_sniffing(self):
        if self.is_running: return
        if not self.iface_to_use:
            print("[SNIFFER] КРИТИЧЕСКАЯ ОШИБКА: Сетевой интерфейс не задан!")
            return
        self.is_running = True
        print(f"[SNIFFER] Запуск захвата на '{self.iface_to_use}' с фильтром: '{self.bpf_filter}'")
        self.sniffer_thread = threading.Thread(
            target=sniff,
            kwargs={'prn': self._packet_callback, 'iface': self.iface_to_use, 'filter': self.bpf_filter, 'store': 0,
                    'stop_filter': lambda _: not self.is_running},
            daemon=True
        )
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.is_running = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1.5)
        print("[SNIFFER] Захват трафика остановлен.")

    def _packet_callback(self, packet):
        # 1. Парсим DNS
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1 and packet.getlayer(DNS).an:
            for answer in packet.getlayer(DNS).an:
                if answer.type == 1:
                    try:
                        self.dns_cache[answer.rdata] = answer.rrname.decode('utf-8').strip('.')
                    except Exception:
                        pass

        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]

        # 2. Инициализируем все переменные
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        pkt_len = len(packet)
        domain = self.dns_cache.get(dst_ip) or self.dns_cache.get(src_ip)

        is_tcp = packet.haslayer(TCP)
        is_udp = packet.haslayer(UDP)
        src_port, dst_port, tcp_flags, protocol = None, None, {}, 'OTHER'

        # 3. Заполняем переменные в зависимости от протокола
        if is_tcp:
            tcp_layer = packet.getlayer(TCP)
            src_port, dst_port = tcp_layer.sport, tcp_layer.dport
            flags_str = str(tcp_layer.flags)
            tcp_flags = {'SYN': 'S' in flags_str, 'ACK': 'A' in flags_str, 'FIN': 'F' in flags_str,
                         'RST': 'R' in flags_str}
            protocol = 'TCP'
        elif is_udp:
            udp_layer = packet.getlayer(UDP)
            src_port, dst_port = udp_layer.sport, udp_layer.dport
            protocol = 'UDP'
        else:
            protocol = ip_layer.get_field('proto').i2s.get(ip_layer.proto, 'OTHER').upper()

        # 4. Создаем универсальный объект PacketData
        pkt_data = PacketData(
            timestamp=datetime.now(), src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, length=pkt_len,
            is_tcp=is_tcp, is_udp=is_udp, tcp_flags=tcp_flags,
            protocol=protocol, domain=domain
        )

        with self.lock:
            self.buffer.append(pkt_data)

    def get_and_clear_buffer(self) -> List[PacketData]:
        with self.lock:
            buffer_snapshot = list(self.buffer)
            self.buffer.clear()
            return buffer_snapshot
