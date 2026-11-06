# port-scanner-recon

Асинхронный CLI-сканер портов на Python с использованием `asyncio` и `rich`.

## Возможности
- Быстрое неблокирующее сканирование портов через `asyncio.Semaphore`.
- Баннер-греббинг для определения версий демонов (SSH, HTTP).
- Проверка параметров SSL/TLS x509 сертификатов (домен, издатель, срок действия).
- Вывод результатов в консоль и сохранение отчетов в JSON.

## Установка зависимостей

```bash
pip install rich cryptography
```

## Использование

```bash
# Сканирование популярных портов
python scanner.py scanme.nmap.org

# Сканирование конкретных портов или диапазонов
python scanner.py scanme.nmap.org -p "22,80,443,8000-8080"

# Сканирование с сохранением отчета в файл
python scanner.py scanme.nmap.org -p "20-100" -o report.json
```
