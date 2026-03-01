# ml_model.py (ИСПРАВЛЕННАЯ версия 2.0)

import numpy as np
import joblib
import os
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

from tf_autoencoder import create_autoencoder
from config import (NUM_FEATURES, NN_HIDDEN_LAYER_SIZE, NN_EPOCHS, NN_LEARNING_RATE, NN_BATCH_SIZE, CONTAMINATION)


# --- Детектор на базе Isolation Forest ---
class IsolationForestDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=CONTAMINATION, random_state=42, n_estimators=100)
        self.scaler = StandardScaler()
        self.initial_threshold = -0.1

    def train_and_save_model(self, X_train, model_path, scaler_path, initial_threshold_percentile=5.0):
        print("[IFOREST] Начало обучения Isolation Forest...")
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled)

        baseline_scores = self.model.decision_function(X_scaled)
        self.initial_threshold = np.percentile(baseline_scores, initial_threshold_percentile)

        # Для IF model_path - это базовое имя. Добавляем .joblib
        joblib.dump(self.model, f"{model_path}.joblib")
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.initial_threshold, f"{model_path}_threshold.joblib")
        print(f"[IFOREST] Обучение завершено. Порог: {self.initial_threshold:.4f}")

    def load_model(self, model_path, scaler_path):
        model_file = f"{model_path}.joblib"
        threshold_file = f"{model_path}_threshold.joblib"
        if not all(os.path.exists(p) for p in [model_file, scaler_path, threshold_file]):
            return False
        self.model = joblib.load(model_file)
        self.scaler = joblib.load(scaler_path)
        self.initial_threshold = joblib.load(threshold_file)
        print(f"[IFOREST] Модель '{model_file}' успешно загружена.")
        return True

    def predict(self, X_new):
        if self.scaler is None: return 0.0
        X_scaled = self.scaler.transform(X_new)
        return self.model.decision_function(X_scaled)[0]


# --- Детектор на базе TensorFlow Autoencoder ---
class TFAutoencoderDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.initial_threshold = 0.1

    def train_and_save_model(self, X_train, model_path, scaler_path, initial_threshold_percentile=95.0):
        print("[TF] Начало обучения TensorFlow Autoencoder...")
        X_scaled = self.scaler.fit_transform(X_train)

        self.model = create_autoencoder(NUM_FEATURES, NN_HIDDEN_LAYER_SIZE, NN_LEARNING_RATE)
        self.model.fit(X_scaled, X_scaled, epochs=NN_EPOCHS, batch_size=NN_BATCH_SIZE, shuffle=True, verbose=2)

        reconstructed_X = self.model.predict(X_scaled, verbose=0)
        reconstruction_errors = tf.keras.losses.MeanSquaredError()(X_scaled, reconstructed_X)
        self.initial_threshold = np.percentile(reconstruction_errors, initial_threshold_percentile)

        # --- ИСПРАВЛЕНИЕ ЗДЕСЬ ---
        # Мы создаем полный путь к файлу с правильным расширением .keras
        keras_model_path = f"{model_path}.keras"
        self.model.save(keras_model_path)
        # -------------------------

        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.initial_threshold, f"{model_path}_threshold.joblib")
        print(f"[TF] Обучение завершено. Модель сохранена в '{keras_model_path}'")

    def load_model(self, model_path, scaler_path):
        # --- ИСПРАВЛЕНИЕ ЗДЕСЬ ---
        # Проверяем и загружаем файл .keras
        keras_model_path = f"{model_path}.keras"
        threshold_file = f"{model_path}_threshold.joblib"
        if not all(os.path.exists(p) for p in [keras_model_path, scaler_path, threshold_file]):
            return False

        self.model = tf.keras.models.load_model(keras_model_path)
        # -------------------------

        self.scaler = joblib.load(scaler_path)
        self.initial_threshold = joblib.load(threshold_file)
        print(f"[TF] Модель '{keras_model_path}' успешно загружена.")
        return True

    def predict(self, X_new):
        if self.model is None or self.scaler is None: return 0.0
        X_scaled = self.scaler.transform(X_new)
        reconstructed = self.model.predict(X_scaled, verbose=0)
        mse = tf.keras.losses.MeanSquaredError()(X_scaled, reconstructed)
        return float(mse.numpy())

