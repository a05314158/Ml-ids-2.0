import time
import os
import json
import traceback
import signal
import sys
from datetime import datetime
from collections import deque, defaultdict
import numpy as np
import ipaddress

from config import *
from sniffer import PacketSniffer
from feature_engineer import extract_features
from ml_model import IsolationForestDetector, TFAutoencoderDetector
from scapy.all import get_if_list

from app import app
from extensions import db
from models import Model, TrafficLog, ActiveState, User

shutdown_flag = False


def signal_handler(sig, frame):
    global shutdown_flag
    shutdown_flag = True


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def is_local_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def log_to_db(user_id: int, message: str, category: str = 'info'):
    try:
        state = db.session.get(ActiveState, user_id)
        if not state:
            state = ActiveState(user_id=user_id)
            db.session.add(state)

        current_log = []
        if state.worker_status_json:
            try:
                data = json.loads(state.worker_status_json)
                current_log = data.get('log', [])
            except:
                pass

        timestamp = datetime.now().strftime('%H:%M:%S')
        log_line = f"[{timestamp}] [{category.upper()}] {message}"
        current_log.insert(0, log_line)
        if len(current_log) > 50: current_log = current_log[:50]

        status_data = json.loads(state.worker_status_json) if state.worker_status_json else {}
        status_data['log'] = current_log
        state.worker_status_json = json.dumps(status_data)
        db.session.commit()
    except:
        pass


class TrafficWorker:
    def __init__(self, user_id: int):
        self.user_id = user_id
        self.sniffer = None
        self.ml_detector = None
        self.active_model_in_memory = None
        self.current_interface = None
        self.local_status = {
            "mode": "Инициализация...", "interface": None, "is_running": True,
            "model_id": None, "current_score": 0.0, "adaptive_threshold": -0.1, "is_anomaly": False
        }

    def update_status_in_db(self):
        try:
            state = db.session.get(ActiveState, self.user_id)
            if not state: return
            current_data = {}
            if state.worker_status_json:
                try:
                    current_data = json.loads(state.worker_status_json)
                except:
                    pass
            current_data.update(self.local_status)
            state.worker_status_json = json.dumps(current_data)
            db.session.commit()
        except:
            pass

    def train_model(self, model_id: int):
        model = db.session.get(Model, model_id)
        if not model: return

        log_to_db(self.user_id, f"Начало обучения: '{model.name}'", "info")
        self.local_status["mode"] = f"Обучение ({model.model_type})"
        self.update_status_in_db()

        X_train_list = []

        # --- ВЫБОР РЕЖИМА: FAST (Тест) или REAL (Продакшен) ---
        USE_FAST_MODE = False  # <--- Поставь False для реального сбора пакетов

        if USE_FAST_MODE:
            log_to_db(self.user_id, "[FAST MODE] Генерация данных...", "warning")
            total_steps = 100
            for i in range(total_steps):
                if shutdown_flag: break
                time.sleep(0.1)  # Быстрая задержка для визуализации

                # Обновляем прогресс
                model.progress = i + 1
                if i % 10 == 0: db.session.commit()

                # Генерируем фейковые данные
                X_train_list.append(np.random.rand(NUM_FEATURES) * 100)

        else:
            # РЕАЛЬНЫЙ РЕЖИМ
            try:
                train_iface = get_if_list()[0]  # Берем первый попавшийся для обучения
                train_sniffer = PacketSniffer()
                train_sniffer.set_config(train_iface, BPF_FILTER)
                train_sniffer.start_sniffing()

                num_cycles = (TRAIN_DURATION_MINUTES * 60) // TIME_WINDOW
                log_to_db(self.user_id, f"Сбор трафика ({num_cycles} циклов)...", "info")

                for i in range(num_cycles):
                    if shutdown_flag: break
                    time.sleep(TIME_WINDOW)

                    # Обновляем прогресс
                    percent = int((i + 1) / num_cycles * 100)
                    model.progress = percent
                    if i % 5 == 0: db.session.commit()

                    snapshot = train_sniffer.get_and_clear_buffer()
                    features = extract_features(snapshot, datetime.now()).features
                    X_train_list.append(features)

                train_sniffer.stop_sniffing()
            except Exception as e:
                log_to_db(self.user_id, f"Ошибка сбора: {e}", "danger")
                return

        if len(X_train_list) < 2:
            log_to_db(self.user_id, "Мало данных. Отмена.", "danger")
            db.session.delete(model)
            db.session.commit()
            return

        try:
            detector = TFAutoencoderDetector() if model.model_type == 'tensorflow' else IsolationForestDetector()
            user_model_dir = os.path.join('models', f'user_{self.user_id}')
            os.makedirs(user_model_dir, exist_ok=True)
            base_filename = f'{model.model_type}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}'
            model_path = os.path.join(user_model_dir, base_filename)
            scaler_path = f"{model_path}_scaler.joblib"

            detector.train_and_save_model(np.array(X_train_list), model_path, scaler_path)

            model.model_path = model_path
            model.progress = 100  # Финал
            model.timestamp = datetime.utcnow()
            log_to_db(self.user_id, "Обучение завершено.", "success")
            db.session.commit()
        except Exception as e:
            log_to_db(self.user_id, f"Ошибка ML: {e}", "danger")
            traceback.print_exc()

    def run(self):
        with app.app_context():
            if not db.session.get(User, self.user_id): return

        while not shutdown_flag:
            try:
                with app.app_context():
                    # 1. Обучение
                    untrained = Model.query.filter_by(user_id=self.user_id, model_path=None).first()
                    if untrained:
                        self.train_model(untrained.id)
                        continue

                    # 2. Мониторинг
                    state = db.session.get(ActiveState, self.user_id)
                    if not state:
                        state = ActiveState(user_id=self.user_id);
                        db.session.add(state);
                        db.session.commit()

                    target_iface = state.interface
                    if not target_iface and get_if_list():
                        ifaces = get_if_list()
                        if ifaces and isinstance(ifaces[0], dict): target_iface = ifaces[0].get('name')

                    if target_iface and (
                            not self.sniffer or not self.sniffer.is_running or self.current_interface != target_iface):
                        if self.sniffer: self.sniffer.stop_sniffing()
                        self.sniffer = PacketSniffer()
                        self.sniffer.set_config(target_iface, BPF_FILTER)
                        self.sniffer.start_sniffing()
                        self.current_interface = target_iface
                        self.local_status["interface"] = "Active"
                        log_to_db(self.user_id, "Сниффер запущен.")

                    if state.is_monitoring and state.active_model_id:
                        if not self.ml_detector or (
                                self.active_model_in_memory and self.active_model_in_memory.id != state.active_model_id):
                            model = db.session.get(Model, state.active_model_id)
                            if model and model.model_path:
                                detector = TFAutoencoderDetector() if model.model_type == 'tensorflow' else IsolationForestDetector()
                                if detector.load_model(model.model_path, f"{model.model_path}_scaler.joblib"):
                                    self.ml_detector = detector
                                    self.active_model_in_memory = model
                                    self.local_status["mode"] = f"Мониторинг ({model.model_type})"
                                    self.local_status["model_id"] = model.id
                                    log_to_db(self.user_id, f"Модель '{model.name}' активна.", "success")
                    else:
                        self.ml_detector = None
                        self.local_status["mode"] = "Сбор статистики"

                    if self.sniffer and self.sniffer.is_running:
                        time.sleep(TIME_WINDOW)
                        snapshot = self.sniffer.get_and_clear_buffer()
                        if snapshot:
                            stats_map = defaultdict(lambda: {"bytes": 0, "pkts": 0, "protos": set(), "domains": set()})
                            for p in snapshot:
                                ip = p.src_ip if is_local_ip(p.src_ip) else (
                                    p.dst_ip if is_local_ip(p.dst_ip) else None)
                                if ip:
                                    stats_map[ip]["bytes"] += p.length
                                    stats_map[ip]["pkts"] += 1
                                    stats_map[ip]["protos"].add(p.protocol)
                                    if p.domain: stats_map[ip]["domains"].add(p.domain)

                            for ip, s in stats_map.items():
                                db.session.add(TrafficLog(user_id=self.user_id, local_ip=ip, total_bytes=s["bytes"],
                                                          packet_count=s["pkts"], protocols=','.join(s["protos"]),
                                                          domains=','.join(s["domains"])))
                            db.session.commit()

                            if self.ml_detector:
                                feats = extract_features(snapshot, datetime.now()).features
                                score = self.ml_detector.predict(np.array([feats]))
                                is_alert = score > self.ml_detector.initial_threshold if self.active_model_in_memory.model_type == 'tensorflow' else score < self.ml_detector.initial_threshold
                                self.local_status.update({"current_score": float(score), "is_anomaly": bool(is_alert)})
                                if is_alert: log_to_db(self.user_id, f"АНОМАЛИЯ! Score: {score:.3f}", "danger")

                    self.update_status_in_db()

            except Exception:
                traceback.print_exc()
                time.sleep(5)

        if self.sniffer: self.sniffer.stop_sniffing()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        TrafficWorker(int(sys.argv[1])).run()