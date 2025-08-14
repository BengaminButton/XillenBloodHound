# XillenBloodhound 🔍

![Java](https://img.shields.io/badge/Java-17-red?logo=openjdk)
![Gradle](https://img.shields.io/badge/Gradle-8.0+-blue?logo=gradle)
![John the Ripper](https://img.shields.io/badge/John_the_Ripper-jumbo-brightgreen)

Простое GUI-приложение для перебора паролей (ZIP/PDF/RDP/WiFi и др.) с генерацией HTML-отчётов и Telegram-уведомлениями.  
Работает поверх **John the Ripper (jumbo)**.

---

## 🚀 Возможности
- Поддержка форматов: **ZIP, PDF, RDP, WiFi** и других (через утилиты `*2john`)
- Генерация детальных **HTML-отчётов**  
- Экспорт результатов в **CSV**  
- Интеграция с **Telegram** для уведомлений  
- Встроенные словари + поддержка пользовательских  
- Кроссплатформенность (Linux/macOS/Windows)

---

## 📦 Требования
- **Java 17** ([установка](https://adoptium.net/))
- **Gradle** ([инструкция](https://gradle.org/install/))
- **John the Ripper (jumbo)** + утилиты (`zip2john`, `pdf2john` и др.) в `PATH`
- Для автootкрытия отчётов:
  - Linux: `xdg-open` / `gio open`  
  - macOS: `open`

---

## ⚡ Быстрый старт
1. Установите зависимости (см. выше)
2. Запустите приложение:
   ```bash
   gradle run

    Демо-режим:

        Нажмите "Создать тестовый ZIP 1234"

        Выберите профиль "Быстрый тест" или метод "Словарь"

        Запустите перебор кнопкой "Начать"

    Результаты появятся в папке reports/ (откроются автоматически).

🛠 Настройка

🔑 Свой словарь

    В поле "Словарь" нажмите "Обзор…"

    Выберите текстовый файл (.txt/.lst/.dic)

        Формат: один пароль на строку

        Если поле пустое — используется встроенный quick.txt

🤖 Telegram-уведомления

    В интерфейсе укажите:

        Telegram Token

        Chat ID → "Сохранить"
        ИЛИ создайте файл config/telegram.properties:
    

token=123456:ABC-DEF...
chat_id=123456789

Проверьте соединение кнопкой "Тест Telegram"
(Если бот не пишет — начните чат с ним вручную)

📂 Структура проекта


/reports       # HTML-отчёты (автогенерация)
/exports       # CSV-экспорт результатов
/config        # Файлы настроек (например, telegram.properties)

📌 Примечания

    Для macOS/Linux: папки открываются через open/xdg-open

    Логотип проекта: "воображение пользователя" 😉

⚠ Важно: Используйте только для легальных целей (например, тестирование своих архивов).
Автор не несёт ответственности за misuse.
