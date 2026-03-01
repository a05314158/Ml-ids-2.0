# data_structures.py (ИСПРАВЛЕННАЯ ВЕРСИЯ 3.0)

from datetime import datetime
from typing import Optional, List, Dict
import numpy as np  # <-- Добавляем импорт numpy


class PacketData:
    """
    Универсальная структура данных для пакета.
    Содержит все поля, необходимые и для ML, и для статистики.
    """

    def __init__(self, timestamp: datetime, src_ip: str, dst_ip: str,
                 src_port: Optional[int], dst_port: Optional[int], length: int,
                 is_tcp: bool, is_udp: bool, tcp_flags: Optional[Dict[str, bool]],
                 protocol: str, domain: Optional[str]):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.is_tcp = is_tcp
        self.is_udp = is_udp
        self.tcp_flags = tcp_flags if tcp_flags is not None else {}
        self.protocol = protocol
        self.domain = domain


class FeatureVector:
    """Хранит агрегированный вектор признаков."""

    def __init__(self, start_time: datetime, end_time: datetime, features: List[float], source_info: dict):
        self.start_time = start_time
        self.end_time = end_time
        self.features = features
        self.source_info = source_info

    # --- ИЗМЕНЕНИЕ: ВОЗВРАЩАЕМ ЭТОТ ВАЖНЫЙ МЕТОД ---
    def get_ml_vector(self) -> np.ndarray:
        """Возвращает numpy-вектор для подачи в модель."""
        # Модели scikit-learn и Keras ожидают на вход 2D-массив,
        # даже если это всего одна запись.
        # [1, 2, 3] -> [[1, 2, 3]]
        return np.array([self.features])
    # ---------------------------------------------------
