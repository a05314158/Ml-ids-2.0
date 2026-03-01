# test_scapy.py (Версия 3.0, с самым надежным импортом)
import sys
print("--- Начинаем финальную проверку Scapy ---")
print(f"Используется Python: {sys.executable}")

try:
    # Импортируем сам scapy для проверки пути
    import scapy
    print(f"Scapy установлен здесь: {scapy.__file__}")

    # ИСПРАВЛЕНО: Правильный, прямой импорт для Windows-функции
    from scapy.arch.windows import get_windows_if_list
    from scapy.config import conf

    print(f"Версия Scapy: {conf.version}")

    print("\n--- Пытаемся получить список интерфейсов напрямую... ---")

    # Вызываем функцию напрямую
    ifaces = get_windows_if_list()

    if not ifaces:
        print("\n!!! РЕЗУЛЬТАТ: Scapy не нашел ни одного интерфейса.")
        print("!!! Это значит, что проблема НЕ в коде, а в окружении.")
        print("!!! Либо Npcap не установлен/не в режиме совместимости, либо что-то блокирует доступ.")
    else:
        print(f"\n--- УСПЕХ! Scapy нашел {len(ifaces)} интерфейсов: ---")
        for iface_data in ifaces:
            # Используем .get() для безопасности, если каких-то ключей нет
            print(f"\n  GUID:          {iface_data.get('guid')}")
            print(f"    Описание:    {iface_data.get('description')}")
            print(f"    IP-адрес:    {iface_data.get('ip_addrs')}")
            print(f"    MAC-адрес:   {iface_data.get('mac')}")

except ImportError as e:
    print(f"\n!!! КРИТИЧЕСКАЯ ОШИБКА ИМПОРТА: {e}")
    print("!!! Либо Scapy не установлен, либо его установка повреждена.")

except Exception as e:
    print(f"\n!!! НЕИЗВЕСТНАЯ КРИТИЧЕСКАЯ ОШИБКА: {e}")
    import traceback
    traceback.print_exc()

print("\n--- Проверка завершена ---")

