# config.py

# --- Настройки захвата трафика ---
BPF_FILTER = "ip or udp"  # Захватываем весь IP и UDP трафик
TIME_WINDOW = 2           # Окно агрегации в секундах (каждые 2 сек делаем вектор)
BURST_WINDOW_SECONDS = 0.5 # <--- ВОТ ЭТОЙ ПЕРЕМЕННОЙ НЕ ХВАТАЛО! (Окно для расчета всплесков)

# --- Настройки ML (Machine Learning) ---
NUM_FEATURES = 13         # Количество признаков (должно совпадать с feature_engineer.py)
TRAIN_DURATION_MINUTES = 1 # Длительность обучения (в минутах). Для демо - 1, для продакшена - 10+
CONTAMINATION = 0.05      # Ожидаемый процент аномалий (5%)

# --- Настройки Нейросети (TensorFlow) ---
NN_HIDDEN_LAYER_SIZE = 8
NN_EPOCHS = 50
NN_LEARNING_RATE = 0.01
NN_BATCH_SIZE = 32

# --- Настройки интерфейса ---
SCORE_HISTORY_SIZE = 100  # Сколько точек хранить на графике в браузере

# --- Пути к файлам (не менять без необходимости) ---
MODEL_PATH = "models/system/model"
SCALER_PATH = "models/system/scaler.joblib"
INITIAL_THRESHOLD_PATH = "models/system/threshold.joblib"