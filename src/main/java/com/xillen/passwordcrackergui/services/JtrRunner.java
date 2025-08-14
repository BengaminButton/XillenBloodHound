package com.xillen.passwordcrackergui.services;

import com.xillen.passwordcrackergui.exec.ProcessUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public class JtrRunner {
    public record Result(boolean success, String password, String showRaw, File hashFile, String error) {}

    public interface Listener {
        void onLog(String line);
        void onProgress(double value, String label); // 0..1 or -1 for indeterminate
        void onFinished(Result result);
    }

    private final Listener listener;
    private volatile Process currentProcess;
    private volatile boolean stopRequested;

    public JtrRunner(Listener listener) {
        this.listener = listener;
    }

    public void runAttack(String type,
                           String method,
                           String targetPath,
                           String dict,
                           String mask,
                           String rainbow) {
        new Thread(() -> {
            try {
                listener.onProgress(-1, "Подготовка...");
                // Автостоп по времени через переменную окружения MAX_RUNTIME_SECONDS
                long maxSeconds = 0;
                try { maxSeconds = Long.parseLong(System.getenv().getOrDefault("MAX_RUNTIME_SECONDS", "0")); } catch (Exception ignored) {}
                final long maxRun = Math.max(0, maxSeconds);
                Thread timer = null;
                if (maxRun > 0) {
                    timer = new Thread(() -> {
                        try { Thread.sleep(maxRun * 1000); } catch (InterruptedException ignored) {}
                        if (!stopRequested) {
                            listener.onLog("Достигнут лимит времени (" + maxRun + " сек). Останавливаю...");
                            stop();
                        }
                    }, "JTR-TIMER");
                    timer.setDaemon(true);
                    timer.start();
                }
                // Проверим наличие john
                requireCommand("john");
                // 1) Извлечь/подготовить хеш
                File hashFile = extractHash(type, targetPath);
                listener.onLog("Хеш подготовлен: " + hashFile.getAbsolutePath());

                // 2) Собрать аргументы john
                List<String> johnCmd = buildJohnArgs(type, method, hashFile, dict, mask, rainbow);
                listener.onLog("Запуск: " + String.join(" ", johnCmd));

                stopRequested = false;
                // 3) Запустить john асинхронно и стримить вывод
                currentProcess = ProcessUtils.runAsync(johnCmd, null,
                        line -> listener.onLog("john: " + line),
                        line -> listener.onLog("john[err]: " + line));
                int code = currentProcess.waitFor();
                listener.onLog("john завершился с кодом: " + code);

                // Если запросили остановку — не делаем --show
                if (stopRequested) {
                    listener.onFinished(new Result(false, null, null, hashFile, "Остановлено пользователем"));
                    return;
                }

                // 4) Попробовать показать найденный пароль
                Result res = showResult(hashFile);
                if (res.success) {
                    listener.onLog("Пароль найден: " + res.password);
                    exportCsv(type, targetPath, method, res.password);
                    generateHtmlReport(type, targetPath, method, res.password, res.showRaw);
                    sendTelegramIfConfigured(type, targetPath, method, res.password);
                } else {
                    listener.onLog("Пароль не найден. Детали --show см. ниже.");
                }
                // 5) Если не нашли — дополнительные попытки (если не остановлено)
                // 5.1 Для ZIP: пробуем альтернативный формат
                if (!res.success && !stopRequested && "ZIP".equals(type)) {
                    // Если первая команда не была с PKZIP — попробуем PKZIP, иначе попробуем zip
                    List<String> altFmt1 = buildJohnArgs("ZIP", method, hashFile, dict, mask, rainbow);
                    boolean hadPkzip = altFmt1.stream().anyMatch(s -> s.equals("--format=PKZIP"));
                    List<String> altFmtCmd = new ArrayList<>(altFmt1);
                    altFmtCmd.removeIf(s -> s.startsWith("--format="));
                    altFmtCmd.add(hadPkzip ? "--format=zip" : "--format=PKZIP");
                    listener.onLog("Пробуем альтернативный ZIP формат: " + String.join(" ", altFmtCmd));
                    currentProcess = ProcessUtils.runAsync(altFmtCmd, null,
                            line -> listener.onLog("john: " + line),
                            line -> listener.onLog("john[err]: " + line));
                    int c = currentProcess.waitFor();
                    listener.onLog("john завершился (альт. формат) с кодом: " + c);
                    if (!stopRequested) {
                        Result r2 = showResult(hashFile);
                        if (r2.success) {
                            listener.onLog("Пароль найден: " + r2.password);
                            exportCsv(type, targetPath, method + " (alt format)", r2.password);
                            generateHtmlReport(type, targetPath, method + " (alt format)", r2.password, r2.showRaw);
                            sendTelegramIfConfigured(type, targetPath, method + " (alt format)", r2.password);
                            listener.onFinished(r2);
                            return;
                        }
                    }
                }

                // 5.2 Попробуем мощный словарь (rockyou), если доступен
                if (!res.success && !stopRequested) {
                    String rock = resolvePowerWordlist();
                    if (rock != null) {
                        listener.onLog("Пробуем словарь: " + rock);
                        List<String> alt = buildJohnArgs(type, "Словарь", hashFile, rock, null, null);
                        listener.onLog("Запуск: " + String.join(" ", alt));
                        currentProcess = ProcessUtils.runAsync(alt, null,
                                line -> listener.onLog("john: " + line),
                                line -> listener.onLog("john[err]: " + line));
                        int code2 = currentProcess.waitFor();
                        listener.onLog("john завершился (rockyou) с кодом: " + code2);
                        if (!stopRequested) {
                            Result r2 = showResult(hashFile);
                            if (r2.success) {
                                listener.onLog("Пароль найден: " + r2.password);
                                exportCsv(type, targetPath, "Словарь (rockyou)", r2.password);
                                generateHtmlReport(type, targetPath, "Словарь (rockyou)", r2.password, r2.showRaw);
                                sendTelegramIfConfigured(type, targetPath, "Словарь (rockyou)", r2.password);
                                listener.onFinished(r2);
                                return;
                            }
                        }
                    }
                }

                // 5.3 Маски PIN 4..6 (если не остановлено)
                if (!res.success && !stopRequested) {
                    String[] masks = {"?d?d?d?d", "?d?d?d?d?d", "?d?d?d?d?d?d"};
                    for (String m : masks) {
                        if (stopRequested) break;
                        listener.onLog("Пробуем маску: " + m);
                        List<String> alt = buildJohnArgs(type, "Маска", hashFile, null, m, null);
                        listener.onLog("Запуск: " + String.join(" ", alt));
                        Result rMask = runAndMaybeShow(type, targetPath, "Маска " + m, alt, hashFile);
                        if (rMask != null) { listener.onFinished(rMask); return; }
                    }
                }

                // 5.4 Wordlist + rules (если не остановлено)
                if (!res.success && !stopRequested) {
                    String baseList = dict != null && !dict.isBlank() ? dict : resolvePowerWordlist();
                    if (baseList != null) {
                        String[] rules = {"best64", "single"};
                        for (String rule : rules) {
                            if (stopRequested) break;
                            List<String> alt = buildBaseArgs(type, hashFile);
                            alt.add("--wordlist=" + baseList);
                            alt.add("--rules=" + rule);
                            listener.onLog("Пробуем wordlist+rules (" + rule + "): " + String.join(" ", alt));
                            Result rr = runAndMaybeShow(type, targetPath, "Словарь+rules=" + rule, alt, hashFile);
                            if (rr != null) { listener.onFinished(rr); return; }
                        }
                    }
                }

                // 5.5 Incremental (Digits 4-8, All 4-8)
                if (!res.success && !stopRequested) {
                    String[][] incs = {
                            {"Digits", "4", "8"},
                            {"All",    "4", "8"}
                    };
                    for (String[] inc : incs) {
                        if (stopRequested) break;
                        String mode = inc[0], min = inc[1], max = inc[2];
                        List<String> alt = buildBaseArgs(type, hashFile);
                        alt.add("--incremental=" + mode);
                        alt.add("--min-length=" + min);
                        alt.add("--max-length=" + max);
                        int cpus = Math.max(1, Math.min(Runtime.getRuntime().availableProcessors(), 4));
                        if (cpus > 1) alt.add("--fork=" + cpus);
                        alt.add(hashFile.getAbsolutePath());
                        listener.onLog("Пробуем incremental=" + mode + " (" + min + "-" + max + "): " + String.join(" ", alt));
                        Result ri = runAndMaybeShow(type, targetPath, "Incremental " + mode, alt, hashFile);
                        if (ri != null) { listener.onFinished(ri); return; }
                    }
                }
                if (!res.success) {
                    // Сгенерируем отчёт о неуспехе с выводом --show для анализа
                    generateHtmlReportFailure(type, targetPath, method, res.showRaw);
                }
                listener.onFinished(res);
            } catch (Exception e) {
                listener.onFinished(new Result(false, null, null, null, e.getMessage()));
            }
        }, "JTR-RUNNER").start();
    }

    private void sendTelegramIfConfigured(String type, String target, String method, String password) {
        try {
            String token = System.getenv("TELEGRAM_TOKEN");
            String chatId = System.getenv("TELEGRAM_CHAT_ID");
            if ((token == null || token.isBlank()) || (chatId == null || chatId.isBlank())) {
                // пробуем конфиг-файл
                File cfg = new File("config/telegram.properties");
                if (cfg.exists()) {
                    java.util.Properties p = new java.util.Properties();
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(cfg)) { p.load(fis); }
                    if (token == null || token.isBlank()) token = p.getProperty("token", token);
                    if (chatId == null || chatId.isBlank()) chatId = p.getProperty("chat_id", chatId);
                }
            }
            if (token == null || token.isBlank() || chatId == null || chatId.isBlank()) return;
            String text = "✅ XillenBloodhound: пароль найден\n" +
                    "Тип: " + type + "\n" +
                    "Цель: " + target + "\n" +
                    "Метод: " + method + "\n" +
                    "Пароль: " + password;
            String curl = "curl -s --max-time 10 -X POST " +
                    "https://api.telegram.org/bot" + token + "/sendMessage " +
                    "-d chat_id=" + chatId + " --data-urlencode \"text=" + text.replace("\"", "\\\"") + "\"";
            List<String> cmd = List.of("bash", "-lc", curl);
            ProcessUtils.run(cmd, null, s -> {}, s -> {});
        } catch (Exception ignored) {}
    }

    // Хелпер: запускает john команду, ждёт завершения и вызывает --show; возвращает Result если найден пароль, иначе null
    private Result runAndMaybeShow(String type, String targetPath, String methodLabel, List<String> cmd, File hashFile) throws IOException, InterruptedException {
        currentProcess = ProcessUtils.runAsync(cmd, null,
                line -> listener.onLog("john: " + line),
                line -> listener.onLog("john[err]: " + line));
        int code = currentProcess.waitFor();
        listener.onLog("john завершился (" + methodLabel + ") с кодом: " + code);
        if (stopRequested) return null;
        Result r = showResult(hashFile);
        if (r.success) {
            listener.onLog("Пароль найден: " + r.password);
            exportCsv(type, targetPath, methodLabel, r.password);
            generateHtmlReport(type, targetPath, methodLabel, r.password, r.showRaw);
            return r;
        }
        return null;
    }

    private void generateHtmlReport(String type, String targetPath, String method, String password, String showRaw) {
        try {
            String dir = System.getenv().getOrDefault("REPORT_DIR", "reports");
            File outDir = new File(dir);
            if (!outDir.exists()) outDir.mkdirs();
            String safeName = new File(targetPath).getName().replaceAll("[^a-zA-Z0-9._-]", "_");
            String ts = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(new java.util.Date());
            File html = new File(outDir, "report_" + ts + "_" + safeName + ".html");
            StringBuilder sb = new StringBuilder();
            sb.append("<!doctype html><html><head><meta charset='utf-8'>");
            sb.append("<title>XillenBloodhound Report</title>");
            sb.append("<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0b0f14;color:#ddd;padding:20px} .card{background:#121821;border:1px solid #273142;border-radius:10px;padding:16px;margin:12px 0} h1{margin:0 0 10px} code,pre{background:#0b1320;color:#a8f;display:block;padding:12px;border-radius:8px;overflow:auto} .k{color:#7fd} .v{color:#fff} .ok{color:#6f6} .warn{color:#fc6}</style></head><body>");
            sb.append("<h1>XillenBloodhound — Отчёт</h1>");
            sb.append("<div class='card'><b class='k'>Статус:</b> <span class='ok'>Пароль найден</span></div>");
            sb.append("<div class='card'><b class='k'>Тип:</b> <span class='v'>").append(htmlEscape(type)).append("</span><br>");
            sb.append("<b class='k'>Цель:</b> <span class='v'>").append(htmlEscape(targetPath)).append("</span><br>");
            sb.append("<b class='k'>Метод:</b> <span class='v'>").append(htmlEscape(method)).append("</span><br>");
            sb.append("<b class='k'>Пароль:</b> <code>").append(htmlEscape(password)).append("</code></div>");
            if (showRaw != null && !showRaw.isBlank()) {
                sb.append("<div class='card'><b class='k'>john --show</b><pre>")
                  .append(htmlEscape(showRaw)).append("</pre></div>");
            }
            sb.append("<div class='card'><small>Сгенерировано ")
              .append(htmlEscape(new java.util.Date().toString()))
              .append(" • XillenBloodhound</small></div>");
            sb.append("</body></html>");
            try (java.io.FileWriter fw = new java.io.FileWriter(html, java.nio.charset.StandardCharsets.UTF_8)) {
                fw.write(sb.toString());
            }
            listener.onLog("HTML-отчёт: " + html.getAbsolutePath());
            openInBrowser(html);
        } catch (Exception e) {
            listener.onLog("Не удалось создать HTML-отчёт: " + e.getMessage());
        }
    }

    private static String htmlEscape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private void generateHtmlReportFailure(String type, String targetPath, String method, String showRaw) {
        try {
            String dir = System.getenv().getOrDefault("REPORT_DIR", "reports");
            File outDir = new File(dir);
            if (!outDir.exists()) outDir.mkdirs();
            String safeName = new File(targetPath).getName().replaceAll("[^a-zA-Z0-9._-]", "_");
            String ts = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(new java.util.Date());
            File html = new File(outDir, "report_" + ts + "_" + safeName + "_FAILED.html");
            StringBuilder sb = new StringBuilder();
            sb.append("<!doctype html><html><head><meta charset='utf-8'>");
            sb.append("<title>XillenBloodhound Report (FAILED)</title>");
            sb.append("<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0b0f14;color:#ddd;padding:20px} .card{background:#121821;border:1px solid #273142;border-radius:10px;padding:16px;margin:12px 0} h1{margin:0 0 10px} code,pre{background:#0b1320;color:#a8f;display:block;padding:12px;border-radius:8px;overflow:auto} .k{color:#7fd} .v{color:#fff} .bad{color:#f66}</style></head><body>");
            sb.append("<h1>XillenBloodhound — Отчёт</h1>");
            sb.append("<div class='card'><b class='k'>Статус:</b> <span class='bad'>Пароль не найден</span></div>");
            sb.append("<div class='card'><b class='k'>Тип:</b> <span class='v'>").append(htmlEscape(type)).append("</span><br>");
            sb.append("<b class='k'>Цель:</b> <span class='v'>").append(htmlEscape(targetPath)).append("</span><br>");
            sb.append("<b class='k'>Метод:</b> <span class='v'>").append(htmlEscape(method)).append("</span></div>");
            if (showRaw != null && !showRaw.isBlank()) {
                sb.append("<div class='card'><b class='k'>john --show</b><pre>")
                  .append(htmlEscape(showRaw)).append("</pre></div>");
            }
            sb.append("<div class='card'><small>Сгенерировано ")
              .append(htmlEscape(new java.util.Date().toString()))
              .append(" • XillenBloodhound</small></div>");
            sb.append("</body></html>");
            try (java.io.FileWriter fw = new java.io.FileWriter(html, java.nio.charset.StandardCharsets.UTF_8)) {
                fw.write(sb.toString());
            }
            listener.onLog("HTML-отчёт (не найден): " + html.getAbsolutePath());
            openInBrowser(html);
        } catch (Exception e) {
            listener.onLog("Не удалось создать HTML-отчёт (не найден): " + e.getMessage());
        }
    }

    private void openInBrowser(File html) {
        try {
            String p = html.getAbsolutePath();
            List<String> cmd = List.of("bash", "-lc", "(xdg-open '" + p + "' || gio open '" + p + "' || open '" + p + "') >/dev/null 2>&1 &");
            ProcessUtils.run(cmd, null, s -> {}, s -> {});
        } catch (Exception ignored) {}
    }

    // Находит расширенный словарь: rockyou.txt или разжимает rockyou.txt.gz во временный файл
    private String resolvePowerWordlist() {
        try {
            Path p1 = Path.of("/usr/share/wordlists/rockyou.txt");
            if (Files.exists(p1)) return p1.toString();
            Path p2 = Path.of("/usr/share/rockyou.txt");
            if (Files.exists(p2)) return p2.toString();
            Path gz = Path.of("/usr/share/wordlists/rockyou.txt.gz");
            if (Files.exists(gz)) {
                Path tmp = Files.createTempFile("rockyou-", ".txt");
                List<String> cmd = List.of("bash", "-lc", "gunzip -c '" + gz + "' > '" + tmp + "'");
                int c = ProcessUtils.run(cmd, null, s -> {}, s -> {});
                if (c == 0 && Files.size(tmp) > 0) return tmp.toString();
            }
        } catch (Exception ignored) {}
        return null;
    }

    public void stop() {
        stopRequested = true;
        try {
            if (currentProcess != null) {
                currentProcess.destroy();
                if (!currentProcess.waitFor(1000, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                    currentProcess.destroyForcibly();
                }
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {}
    }

    private File extractHash(String type, String targetPath) throws IOException, InterruptedException {
        String tool;
        switch (Objects.requireNonNullElse(type, "")) {
            case "ZIP" -> tool = "zip2john";
            case "PDF" -> tool = "pdf2john";
            case "RDP" -> tool = "rdp2john"; // в наборе jumbo
            case "WiFi" -> tool = "wpapcap2john"; // для pcap
            case "SSH" -> tool = "ssh2john"; // приватные ключи OpenSSH
            case "Bitcoin" -> tool = "bitcoin2john"; // wallet.dat
            case "VeraCrypt" -> tool = "veracrypt2john";
            case "LUKS" -> tool = "luks2john";
            case "BitLocker" -> tool = "bitlocker2john";
            case "RAW" -> {
                // Считаем, что targetPath уже указывает на файл с хешем/строкой
                File f = new File(targetPath);
                if (f.exists()) return f;
                // Если это строка, возможно это base64/hex — декодируем в отдельный файл
                String s = targetPath.trim();
                byte[] data = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                try {
                    if (isHexString(s)) {
                        data = hexToBytes(s);
                    } else if (isBase64String(s)) {
                        data = java.util.Base64.getDecoder().decode(s);
                    }
                } catch (Exception ignored) {}
                Path tmp = Files.createTempFile("hash-raw-", ".bin");
                Files.write(tmp, data);
                return tmp.toFile();
            }
            default -> throw new IllegalArgumentException("Неизвестный тип: " + type);
        }
        // проверим наличие соответствующего *2john
        requireCommand(tool);
        List<String> cmd = List.of(tool, targetPath);
        listener.onLog("Извлечение хеша: " + String.join(" ", cmd));
        Path tmp = Files.createTempFile("hash-", ".txt");
        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        int code = ProcessUtils.run(cmd, null, out::append, err::append);
        if (code != 0 || out.length() == 0) {
            throw new IOException("Не удалось извлечь хеш: code=" + code + ", err=" + err);
        }
        Files.writeString(tmp, out.toString(), StandardCharsets.UTF_8);
        return tmp.toFile();
    }

    private List<String> buildJohnArgs(String type, String method, File hashFile,
                                       String dict, String mask, String rainbow) {
        List<String> args = buildBaseArgs(type, hashFile);
        // метод
        if (method != null) {
            switch (method) {
                case "Dictionary", "Словарь" -> {
                    if (dict != null && !dict.isBlank()) args.add("--wordlist=" + dict);
                }
                case "Mask", "Маска" -> {
                    if (mask != null && !mask.isBlank()) args.add("--mask=" + mask);
                }
                case "Гибрид (Словарь+Маска)" -> {
                    if (dict != null && !dict.isBlank()) args.add("--wordlist=" + dict);
                    if (mask != null && !mask.isBlank()) args.add("--mask=" + mask);
                }
                case "Rainbow Table", "Радужные таблицы" -> {
                    // john не использует "--tables" напрямую; это заглушка интеграции с внешними таблицами
                    // Можно подключить сторонний генератор кандидатов и подавать во stdin, если потребуется
                }
            }
        }
        // многопроцессорность: --fork=N (ограничим до 4 по умолчанию)
        int cpus = Math.max(1, Math.min(Runtime.getRuntime().availableProcessors(), 4));
        if (cpus > 1) args.add("--fork=" + cpus);
        args.add(hashFile.getAbsolutePath());
        return args;
    }

    // Базовые аргументы john с учётом формата для заданного типа
    private List<String> buildBaseArgs(String type, File hashFile) {
        List<String> args = new ArrayList<>();
        args.add("john");
        switch (Objects.requireNonNullElse(type, "")) {
            case "ZIP" -> {
                try {
                    String sample = Files.readString(hashFile.toPath());
                    String low = sample.toLowerCase();
                    if (low.contains("$pkzip$") || low.contains("pkzip")) {
                        args.add("--format=PKZIP");
                    } else if (low.contains("$zip2$") || low.contains("$zip$")) {
                        args.add("--format=zip");
                    } else {
                        // оставляем autodetect, john сам подберёт
                    }
                } catch (IOException ignored) {}
            }
            case "PDF" -> args.add("--format=pdf");
            case "RDP" -> args.add("--format=NT");
            case "WiFi" -> args.add("--format=wpapsk");
            case "SSH" -> args.add("--format=ssh");
            case "Bitcoin" -> args.add("--format=bitcoin");
            case "VeraCrypt" -> args.add("--format=veracrypt");
            case "LUKS" -> args.add("--format=luks");
            case "BitLocker" -> args.add("--format=bitlocker");
            case "RAW" -> { /* формат не задаём — пускай autodetect/профили */ }
        }
        return args;
    }

    private static boolean isHexString(String s) {
        if (s == null || s.isBlank()) return false;
        String t = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
        if ((t.length() & 1) == 1) return false; // чётная длина
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return t.length() >= 2;
    }

    private static byte[] hexToBytes(String s) {
        String t = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
        int len = t.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(t.charAt(i), 16);
            int lo = Character.digit(t.charAt(i + 1), 16);
            out[i / 2] = (byte) ((hi << 4) + lo);
        }
        return out;
    }

    private static boolean isBase64String(String s) {
        if (s == null || s.isBlank()) return false;
        // Быстрая эвристика: валидные base64 символы и паддинг '='
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            if (!ok) return false;
        }
        // Попробуем декодировать
        try {
            java.util.Base64.getDecoder().decode(s);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Result showResult(File hashFile) throws IOException, InterruptedException {
        List<String> show = List.of("john", "--show", hashFile.getAbsolutePath());
        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        int code = ProcessUtils.run(show, null, s -> out.append(s).append('\n'), s -> err.append(s).append('\n'));
        if (code == 0) {
            // Формат john --show: filename:password или user:password:... в зависимости от формата
            AtomicReference<String> pwd = new AtomicReference<>();
            out.toString().lines().forEach(l -> {
                if (l.contains(":")) {
                    String[] parts = l.split(":", 3);
                    if (parts.length >= 2 && parts[1] != null && !parts[1].isBlank()) {
                        pwd.compareAndSet(null, parts[1]);
                    }
                }
            });
            if (pwd.get() != null) {
                return new Result(true, pwd.get(), out.toString(), hashFile, null);
            }
            return new Result(false, null, out.toString(), hashFile, null);
        }
        return new Result(false, null, out.toString() + "\nERR:\n" + err, hashFile, "john --show exit=" + code);
    }

    private void exportCsv(String type, String target, String method, String password) {
        try {
            File dir = new File("exports");
            if (!dir.exists()) dir.mkdirs();
            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            File csv = new File(dir, "results-" + ts + ".csv");
            try (FileWriter fw = new FileWriter(csv, StandardCharsets.UTF_8)) {
                fw.write("type,target,method,password\n");
                fw.write(escape(type) + "," + escape(target) + "," + escape(method) + "," + escape(password) + "\n");
            }
            listener.onLog("Результаты экспортированы: " + csv.getAbsolutePath());
        } catch (Exception e) {
            listener.onLog("Не удалось экспортировать CSV: " + e.getMessage());
        }
    }

    private String escape(String s) {
        if (s == null) return "";
        String q = s.replace("\"", "\"\"");
        return '"' + q + '"';
    }

    private void requireCommand(String name) throws IOException, InterruptedException {
        List<String> check = List.of("bash", "-lc", "command -v " + name + " || which " + name);
        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        int code = ProcessUtils.run(check, null, s -> out.append(s).append('\n'), s -> err.append(s).append('\n'));
        if (code != 0 || out.toString().trim().isEmpty()) {
            throw new IOException("Не найден инструмент '" + name + "' в PATH. Установите John the Ripper Jumbo и утилиты *2john.");
        }
    }
}
