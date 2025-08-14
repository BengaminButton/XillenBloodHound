package com.xillen.passwordcrackergui.controllers;

import com.xillen.passwordcrackergui.nativebinding.NativeBindings;
import com.xillen.passwordcrackergui.services.JtrService;
import com.xillen.passwordcrackergui.services.JtrRunner;
import com.xillen.passwordcrackergui.services.MongoService;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.StackPane;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

public class MainController {
    @FXML private Label authorLabel;
    @FXML private ComboBox<String> targetType;
    @FXML private TextField targetPath;
    @FXML private ComboBox<String> attackMethod;
    @FXML private TextField dictionaryPath;
    @FXML private TextField maskPattern;
    @FXML private TextField rainbowTablePath;
    @FXML private ComboBox<String> profilePreset;
    @FXML private TextField telegramTokenField;
    @FXML private TextField telegramChatIdField;
    @FXML private TextArea logArea;
    @FXML private ProgressBar progressBar;
    @FXML private Label progressLabel;
    @FXML private Button startBtn;
    @FXML private Button stopBtn;
    @FXML private StackPane vizPane;

    private final MongoService mongo = new MongoService();
    private final JtrService jtr = new JtrService();
    private JtrRunner currentRunner;

    @FXML
    public void initialize() {
        authorLabel.setText("Авторы: t.me/XillenAdapter • https://github.com/BengaminButton");
        targetType.getItems().addAll("ZIP", "PDF", "RDP", "WiFi", "SSH", "Bitcoin", "VeraCrypt", "LUKS", "BitLocker", "RAW");
        attackMethod.getItems().addAll("Словарь", "Маска", "Гибрид (Словарь+Маска)", "Радужные таблицы");
        attackMethod.getSelectionModel().selectFirst();
        attackMethod.getSelectionModel().selectedItemProperty().addListener((obs, o, n) -> updateAttackInputs(n));
        updateAttackInputs(null);
        profilePreset.getItems().addAll(
                "Быстрый тест (1234 и частые)",
                "PIN 0000-9999 (маска)",
                "Частые пароли (встроенный словарь)"
        );
        ensureTelegramConfigTemplate();
        loadTelegramConfigIntoFields();
        String reportDir = System.getenv().getOrDefault("REPORT_DIR", "reports");
        log("Каталог отчётов: " + new File(reportDir).getAbsolutePath());
        log("Готово. 1) Тип цели. 2) Файл/хеш. 3) Метод или Профиль. 4) 'Начать'. Нажмите 'Руководство' для подробностей.");
    }

    private void ensureTelegramConfigTemplate() {
        try {
            File cfgDir = new File("config");
            if (!cfgDir.exists()) cfgDir.mkdirs();
            File cfg = new File(cfgDir, "telegram.properties");
            if (!cfg.exists()) {
                try (FileWriter fw = new FileWriter(cfg)) {
                    fw.write("# Telegram bot settings\n");
                    fw.write("# token=123456:ABC-DEF...\n");
                    fw.write("# chat_id=123456789\n");
                }
                log("Создан шаблон конфига Telegram: " + cfg.getAbsolutePath());
            }
        } catch (Exception e) {
            log("Не удалось создать шаблон конфига Telegram: " + e.getMessage());
        }
    }

    private void loadTelegramConfigIntoFields() {
        try {
            String token = System.getenv("TELEGRAM_TOKEN");
            String chatId = System.getenv("TELEGRAM_CHAT_ID");
            File cfg = new File("config/telegram.properties");
            if (cfg.exists()) {
                java.util.Properties p = new java.util.Properties();
                try (java.io.FileInputStream fis = new java.io.FileInputStream(cfg)) { p.load(fis); }
                if (token == null || token.isBlank()) token = p.getProperty("token", token);
                if (chatId == null || chatId.isBlank()) chatId = p.getProperty("chat_id", chatId);
            }
            if (telegramTokenField != null) telegramTokenField.setText(token != null ? token : "");
            if (telegramChatIdField != null) telegramChatIdField.setText(chatId != null ? chatId : "");
        } catch (Exception e) {
            log("Не удалось загрузить настройки Telegram: " + e.getMessage());
        }
    }

    @FXML
    private void onSaveTelegram() {
        try {
            String token = telegramTokenField != null ? telegramTokenField.getText().trim() : "";
            String chatId = telegramChatIdField != null ? telegramChatIdField.getText().trim() : "";
            if (token.isEmpty() || chatId.isEmpty()) {
                alert("Укажите token и chat_id");
                return;
            }
            File cfgDir = new File("config");
            if (!cfgDir.exists()) cfgDir.mkdirs();
            File cfg = new File(cfgDir, "telegram.properties");
            java.util.Properties p = new java.util.Properties();
            p.setProperty("token", token);
            p.setProperty("chat_id", chatId);
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(cfg)) {
                p.store(fos, "XillenBloodhound Telegram settings");
            }
            log("Сохранены настройки Telegram: " + cfg.getAbsolutePath());
        } catch (Exception e) {
            alert("Не удалось сохранить настройки Telegram: " + e.getMessage());
        }
    }

    @FXML
    private void onCreateTestZip() {
        try {
            File dir = new File("testdata");
            if (!dir.exists()) dir.mkdirs();
            File src = new File(dir, "secret.txt");
            try (FileWriter fw = new FileWriter(src)) { fw.write("demo secret data\n"); }
            File zip = new File(dir, "zip1234.zip");
            // Используем системную zip утилиту с -P 1234
            String[] cmd = {"bash", "-lc", "zip -j -P 1234 '" + zip.getAbsolutePath() + "' '" + src.getAbsolutePath() + "'"};
            Process p = new ProcessBuilder(cmd).directory(new File(".")).start();
            int code = p.waitFor();
            if (code == 0 && zip.exists()) {
                targetPath.setText(zip.getAbsolutePath());
                log("Создан тестовый архив: " + zip.getAbsolutePath());
                alert("Создан архив с паролем 1234: " + zip.getAbsolutePath());
            } else {
                alert("Не удалось создать тестовый ZIP. Проверьте наличие утилиты 'zip'.");
            }
        } catch (Exception e) {
            alert("Ошибка создания тестового ZIP: " + e.getMessage());
        }
    }

    private void updateAttackInputs(String method) {
        boolean dict = "Словарь".equals(method) || "Гибрид (Словарь+Маска)".equals(method);
        boolean mask = "Маска".equals(method) || "Гибрид (Словарь+Маска)".equals(method);
        boolean rainbow = "Радужные таблицы".equals(method);
        dictionaryPath.setDisable(!dict);
        maskPattern.setDisable(!mask);
        rainbowTablePath.setDisable(!rainbow);
    }

    @FXML
    private void onBrowseTarget() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Выберите файл");
        fc.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Все файлы", "*.*"),
                new FileChooser.ExtensionFilter("ZIP", "*.zip"),
                new FileChooser.ExtensionFilter("PDF", "*.pdf"),
                new FileChooser.ExtensionFilter("VeraCrypt", "*.hc", "*.vc"),
                new FileChooser.ExtensionFilter("LUKS", "*"),
                new FileChooser.ExtensionFilter("BitLocker", "*.bek", "*.fve", "*.vhd", "*.vhdx")
        );
        Window w = targetPath.getScene() != null ? targetPath.getScene().getWindow() : null;
        var file = fc.showOpenDialog(w);
        if (file != null) {
            targetPath.setText(file.getAbsolutePath());
            log("Выбран файл: " + file.getAbsolutePath());
        }
    }

    @FXML
    private void onProfileChanged() {
        String p = profilePreset.getValue();
        if (p == null) return;
        switch (p) {
            case "Быстрый тест (1234 и частые)" -> {
                attackMethod.getSelectionModel().select("Словарь");
                dictionaryPath.setText(resolveQuickWordlistPath());
                log("Профиль: Быстрый тест. Словарь установлен на встроенный 'quick.txt'.");
            }
            case "PIN 0000-9999 (маска)" -> {
                attackMethod.getSelectionModel().select("Маска");
                maskPattern.setText("?d?d?d?d");
                log("Профиль: PIN 0000-9999. Маска установлена на ?d?d?d?d.");
            }
            case "Частые пароли (встроенный словарь)" -> {
                attackMethod.getSelectionModel().select("Словарь");
                dictionaryPath.setText(resolveQuickWordlistPath());
                log("Профиль: Частые пароли. Словарь установлен на встроенный 'quick.txt'.");
            }
        }
    }

    @FXML
    private void onHelp() {
        String msg = "Руководство\n\n" +
                "— Тип цели: ZIP/PDF/RDP/WiFi.\n" +
                "— Файл/хеш: укажите архив/файл (для WiFi — pcap).\n" +
                "— Метод атаки:\n" +
                "   • Словарь — перебор из файла списка паролей (wordlist).\n" +
                "   • Маска — генерирует кандидатов по шаблону (?d=цифра, ?l=буква).\n" +
                "   • Радужные таблицы — точка интеграции с внешними таблицами.\n" +
                "— Профиль: быстрые пресеты (настройки заполняются автоматически).\n\n" +
                "Собственный словарь: в поле ‘Словарь’ нажмите ‘Обзор...’ и выберите свой файл.\n" +
                "Файл словаря — обычный текстовый .txt, ОДИН пароль в каждой строке. Поддерживаются также расширения .lst/.dic.\n\n" +
                "Примеры (быстрый старт):\n" +
                "• Быстрый тест: выберите профиль 'Быстрый тест' и нажмите Начать.\n" +
                "• PIN 4 цифры: профиль PIN 0000-9999.\n\n" +
                "Кнопка 'Создать тестовый ZIP 1234' создаёт архив testdata/zip1234.zip с паролем 1234 и подставляет путь.\n" +
                "Примечание: требуется установленный John the Ripper (jumbo) и утилиты *2john.";
        Alert a = new Alert(Alert.AlertType.INFORMATION, msg, ButtonType.OK);
        a.setHeaderText("Руководство");
        a.showAndWait();
    }

    @FXML
    private void onStart() {
        String target = targetPath.getText();
        String type = targetType.getValue();
        String method = attackMethod.getValue();
        if (type == null) {
            alert("Выберите тип цели (ZIP/PDF/RDP/WiFi).");
            return;
        }
        if (target == null || target.isBlank()) {
            alert("Укажите путь к файлу или хешу.");
            return;
        }
        if (method == null) {
            alert("Выберите метод атаки.");
            return;
        }
        startBtn.setDisable(true);
        stopBtn.setDisable(false);
        progressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        progressLabel.setText("Запуск...");

        log("Цель: [" + type + "] " + target);
        log("Метод: " + method);
        switch (method) {
            case "Словарь" -> log("Словарь: " + dictionaryPath.getText());
            case "Маска" -> log("Маска: " + maskPattern.getText());
            case "Радужные таблицы" -> log("Радужная таблица: " + rainbowTablePath.getText());
        }

        currentRunner = new JtrRunner(new JtrRunner.Listener() {
            @Override public void onLog(String line) {
                log(line);
            }
            @Override public void onProgress(double value, String label) {
                Platform.runLater(() -> {
                    if (value < 0) progressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
                    else progressBar.setProgress(value);
                    progressLabel.setText(label);
                });
            }
            @Override public void onFinished(JtrRunner.Result result) {
                Platform.runLater(() -> {
                    startBtn.setDisable(false);
                    stopBtn.setDisable(true);
                });
                if (result.success()) {
                    log("Готово. Пароль найден: " + result.password());
                    try {
                        mongo.saveResult(type, target, method, true, result.password());
                        log("Результат сохранён в MongoDB.");
                    } catch (Exception e) {
                        log("Не удалось сохранить результат в MongoDB: " + e.getMessage());
                    }
                } else {
                    log("Завершено без найденного пароля.\n" + (result.showRaw() == null ? "" : result.showRaw()));
                }
            }
        });
        String dict = dictionaryPath.getText();
        if ((dict == null || dict.isBlank()) && "Словарь".equals(method)) {
            // если словарь не указан, используем встроенный quick.txt
            dict = resolveQuickWordlistPath();
            dictionaryPath.setText(dict);
            log("Использую встроенный словарь: " + dict);
        }
        currentRunner.runAttack(type, method, target, dict, maskPattern.getText(), rainbowTablePath.getText());
    }

    @FXML
    private void onStop() {
        try {
            if (currentRunner != null) currentRunner.stop();
        } catch (Throwable ignored) {}
        progressLabel.setText("Остановлено");
        progressBar.setProgress(0);
        startBtn.setDisable(false);
        stopBtn.setDisable(true);
    }

    @FXML
    private void onOpenReports() {
        try {
            String dir = System.getenv().getOrDefault("REPORT_DIR", "reports");
            File folder = new File(dir);
            if (!folder.exists()) folder.mkdirs();
            String abs = folder.getAbsolutePath();
            String[] cmd = {"bash", "-lc", "(xdg-open '" + abs + "' || gio open '" + abs + "' || open '" + abs + "') >/dev/null 2>&1 &"};
            new ProcessBuilder(cmd).start();
            log("Открыл каталог отчётов: " + abs);
        } catch (Exception e) {
            alert("Не удалось открыть каталог отчётов: " + e.getMessage());
        }
    }

    @FXML
    private void onTestTelegram() {
        try {
            // load token/chatId: prefer UI fields, then ENV, then config file
            String token = telegramTokenField != null ? telegramTokenField.getText().trim() : null;
            String chatId = telegramChatIdField != null ? telegramChatIdField.getText().trim() : null;
            if (token == null || token.isBlank()) token = System.getenv("TELEGRAM_TOKEN");
            if (chatId == null || chatId.isBlank()) chatId = System.getenv("TELEGRAM_CHAT_ID");
            try {
                File cfg = new File("config/telegram.properties");
                if ((token == null || token.isBlank() || chatId == null || chatId.isBlank()) && cfg.exists()) {
                    java.util.Properties p = new java.util.Properties();
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(cfg)) { p.load(fis); }
                    if (token == null || token.isBlank()) token = p.getProperty("token", token);
                    if (chatId == null || chatId.isBlank()) chatId = p.getProperty("chat_id", chatId);
                }
            } catch (Exception ignored) {}
            if (token == null || token.isBlank() || chatId == null || chatId.isBlank()) {
                alert("Не настроен Telegram. Укажите TELEGRAM_TOKEN и TELEGRAM_CHAT_ID или заполните config/telegram.properties");
                return;
            }
            String text = "🧪 Тест XillenBloodhound\nВремя: " + new java.util.Date();
            // Use POST + --data-urlencode to safely handle Unicode and special characters
            String curl = "curl -s --max-time 10 -X POST " +
                    "https://api.telegram.org/bot" + token + "/sendMessage " +
                    "-d chat_id=" + chatId + " --data-urlencode \"text=" + text.replace("\"", "\\\"") + "\"";
            String[] cmd = {"bash", "-lc", curl};
            Process p = new ProcessBuilder(cmd).start();
            int code = p.waitFor();
            if (code == 0) log("Отправлено тестовое сообщение Telegram.");
            else log("Ошибка отправки тестового сообщения Telegram: код " + code);
        } catch (Exception e) {
            log("Ошибка Telegram: " + e.getMessage());
        }
    }

    @FXML
    private void onBrowseDictionary() {
        try {
            FileChooser fc = new FileChooser();
            fc.setTitle("Выберите словарь (txt)");
            fc.getExtensionFilters().addAll(
                    new FileChooser.ExtensionFilter("Текстовые файлы", "*.txt", "*.lst", "*.dic"),
                    new FileChooser.ExtensionFilter("Все файлы", "*.*")
            );
            Window w = dictionaryPath.getScene() != null ? dictionaryPath.getScene().getWindow() : null;
            File f = fc.showOpenDialog(w);
            if (f != null) {
                dictionaryPath.setText(f.getAbsolutePath());
                log("Выбран словарь: " + f.getAbsolutePath());
            }
        } catch (Exception e) {
            alert("Не удалось выбрать словарь: " + e.getMessage());
        }
    }

    private void alert(String msg) {
        Alert a = new Alert(Alert.AlertType.INFORMATION, msg, ButtonType.OK);
        a.setHeaderText(null);
        a.showAndWait();
    }

    private void log(String msg) {
        Platform.runLater(() -> {
            logArea.appendText(msg + "\n");
        });
    }

    // Возвращает путь к встроенному небольшому словарю quick.txt.
    // Если ресурс лежит как обычный файл — используем его напрямую,
    // иначе копируем во временную директорию и возвращаем путь к копии.
    private String resolveQuickWordlistPath() {
        try {
            var url = getClass().getResource("/wordlists/quick.txt");
            if (url == null) throw new FileNotFoundException("quick.txt not found in resources");
            try {
                File f = new File(url.toURI());
                if (f.exists()) return f.getAbsolutePath();
            } catch (URISyntaxException ignored) {}
            try (InputStream in = getClass().getResourceAsStream("/wordlists/quick.txt")) {
                if (in == null) throw new FileNotFoundException("quick.txt stream is null");
                Path tmp = Files.createTempFile("quick-wordlist-", ".txt");
                try (OutputStream out = Files.newOutputStream(tmp)) {
                    in.transferTo(out);
                }
                return tmp.toAbsolutePath().toString();
            }
        } catch (Exception e) {
            log("Не удалось подготовить встроенный словарь: " + e.getMessage());
            return "";
        }
    }
}
