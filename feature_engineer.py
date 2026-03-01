#feature_engineer
import numpy as np
import math
from typing import List
from collections import Counter
from datetime import datetime, timedelta
# --- Добавляем модуль для временных расчётов ---
import pandas as pd

from data_structures import PacketData, FeatureVector
from config import BURST_WINDOW_SECONDS # Импортируем константу

def shannon_entropy(data: List) -> float:
    """
    Расчет энтропии Шеннона для списка элементов.
    Используется для Entropy_DPort.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy

def extract_features(packet_snapshot: List[PacketData], window_end_time: datetime) -> FeatureVector:
    """
    Преобразует список сырых пакетов (за Time-Window) в единый вектор признаков (13 признаков).
    (Фаза 3.2 + Улучшения + Временные признаки)
    """
    if not packet_snapshot:
        # Если пакетов нет, возвращаем вектор из нулей для ML-модели
        return FeatureVector(
            start_time=window_end_time,
            end_time=window_end_time,
            features=[0.0] * 13,  # <--- Теперь 13 нулей
            source_info={'Total_Packets': 0}
        )

    # Сортируем пакеты по времени прибытия для расчёта временных признаков
    sorted_packets = sorted(packet_snapshot, key=lambda p: p.timestamp)

    # Инициализация структур для расчета
    total_packets = len(sorted_packets)
    total_bytes = 0
    packet_lengths = []
    dst_ports = []
    tcp_packets = []
    udp_packets = []
    timestamps = [] # <--- Новый список для временных меток

    other_ip_packets = 0
    unique_src_ips = set()
    unique_dst_ips = set()

    start_time = sorted_packets[0].timestamp

    # Итерация и сбор данных
    for pkt in sorted_packets:
        total_bytes += pkt.length
        packet_lengths.append(pkt.length)
        unique_src_ips.add(pkt.src_ip)
        unique_dst_ips.add(pkt.dst_ip)
        timestamps.append(pkt.timestamp) # <--- Сохраняем время

        if pkt.is_tcp:
            tcp_packets.append(pkt)
            if pkt.dst_port is not None:
                dst_ports.append(pkt.dst_port)
        elif pkt.is_udp:
            udp_packets.append(pkt)
            if pkt.dst_port is not None:
                dst_ports.append(pkt.dst_port)
        else:
            other_ip_packets += 1

    # --- РАСЧЁТ СТАТИСТИЧЕСКИХ ПРИЗНАКОВ (1-10) ---
    feature_1 = float(total_packets)
    feature_2 = float(total_bytes)
    feature_3 = np.median(packet_lengths) if packet_lengths else 0.0
    feature_4 = shannon_entropy(dst_ports)
    syn_count = sum(1 for pkt in tcp_packets if pkt.tcp_flags.get('SYN', False) and not pkt.tcp_flags.get('ACK', False))
    feature_5 = syn_count / len(tcp_packets) if len(tcp_packets) > 0 else 0.0
    feature_6 = len(udp_packets) / total_packets
    feature_7 = float(len(unique_src_ips))
    feature_8 = len(tcp_packets) / total_packets
    feature_9 = other_ip_packets / total_packets
    feature_10 = float(len(unique_dst_ips))

    # --- РАСЧЁТ ВРЕМЕННЫХ ПРИЗНАКОВ (11-13) ---
    if len(timestamps) > 1:
        # Преобразуем в pandas Series для удобства
        ts_series = pd.Series([t.timestamp() for t in timestamps])
        inter_arrival_times = ts_series.diff().dropna() # Получаем интервалы

        # 11. Mean_Inter_Arrival_Time
        feature_11 = inter_arrival_times.mean() if not inter_arrival_times.empty else 0.0

        # 12. Std_Inter_Arrival_Time
        feature_12 = inter_arrival_times.std() if not inter_arrival_times.empty else 0.0

        # 13. Burst_Rate (максимум пакетов за BURST_WINDOW_SECONDS)
        burst_rates = []
        if not inter_arrival_times.empty:
            window_td = timedelta(seconds=BURST_WINDOW_SECONDS)
            for i, ts in enumerate(timestamps):
                # Считаем пакеты в окне [ts - window_td, ts]
                window_start = ts - window_td
                count_in_window = sum(1 for pkt_ts in timestamps if window_start <= pkt_ts <= ts)
                burst_rates.append(count_in_window)
        feature_13 = max(burst_rates) if burst_rates else 0.0
    else:
        # Если пакетов < 2, невозможно рассчитать интервалы
        feature_11 = 0.0
        feature_12 = 0.0
        feature_13 = 0.0

    # Финальный вектор признаков
    feature_vector_list = [
        feature_1, feature_2, feature_3, feature_4,
        feature_5, feature_6, feature_7, feature_8,
        feature_9, feature_10, feature_11, feature_12, feature_13
    ]

    # Дополнительная информация для логирования (можно обновить)
    source_info = {
        'Total_Packets': total_packets,
        'Unique_Src_IPs': feature_7,
        'Unique_Dst_IPs': feature_10,
        'Entropy_DPort': feature_4,
        'Unique_DPorts_Count': len(Counter(dst_ports)),
        'Most_Active_IP': Counter([p.src_ip for p in sorted_packets]).most_common(1)[0][0]
        if total_packets > 0 else "N/A",
        # --- Добавляем информацию о временных признаках ---
        'Mean_Inter_Arrival_Time': feature_11,
        'Std_Inter_Arrival_Time': feature_12,
        'Max_Burst_Rate': feature_13
    }

    return FeatureVector(
        start_time=start_time,
        end_time=window_end_time,
        features=feature_vector_list,
        source_info=source_info
    )
