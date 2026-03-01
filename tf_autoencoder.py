# tf_autoencoder.py

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense

def create_autoencoder(input_size: int, hidden_size: int, learning_rate: float) -> Model:
    """
    Создает, компилирует и возвращает модель автоэнкодера на Keras.

    Args:
        input_size: Количество признаков на входе (например, 13).
        hidden_size: Размер сжатого представления.
        learning_rate: Скорость обучения.

    Returns:
        Скомпилированная Keras модель.
    """
    # --- Архитектура ---
    # Входной слой
    input_layer = Input(shape=(input_size,), name="input")

    # Слой кодировщика (Encoder)
    encoded = Dense(hidden_size, activation='relu', name="encoded_layer")(input_layer)

    # Слой декодировщика (Decoder)
    decoded = Dense(input_size, activation='sigmoid', name="output_reconstruction")(encoded)

    # --- Сборка модели ---
    autoencoder = Model(inputs=input_layer, outputs=decoded, name="Autoencoder")

    # --- Компиляция ---
    # Создаем оптимизатор Adam с заданной скоростью обучения
    optimizer = tf.keras.optimizers.Adam(learning_rate=learning_rate)

    # Компилируем модель. Наша цель - минимизировать среднеквадратичную ошибку (mse)
    # между входом и восстановленным выходом.
    autoencoder.compile(optimizer=optimizer, loss='mean_squared_error')

    print("[TF] Модель Keras Autoencoder успешно создана и скомпилирована.")
    autoencoder.summary() # Выводим архитектуру модели в консоль

    return autoencoder
