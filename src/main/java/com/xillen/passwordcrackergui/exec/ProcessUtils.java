package com.xillen.passwordcrackergui.exec;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class ProcessUtils {
    public static int run(List<String> command, File workingDir, Consumer<String> stdout, Consumer<String> stderr) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        if (workingDir != null) pb.directory(workingDir);
        pb.redirectErrorStream(false);
        Process p = pb.start();
        var ex = Executors.newFixedThreadPool(2);
        ex.submit(() -> copy(p.getInputStream(), stdout));
        ex.submit(() -> copy(p.getErrorStream(), stderr));
        int code = p.waitFor();
        ex.shutdownNow();
        return code;
    }

    // Запускает процесс асинхронно, возвращает дескриптор Process.
    // Потоки stdout/stderr читаются в фоновых задачах до завершения процесса.
    public static Process runAsync(List<String> command, File workingDir, Consumer<String> stdout, Consumer<String> stderr) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(command);
        if (workingDir != null) pb.directory(workingDir);
        pb.redirectErrorStream(false);
        Process p = pb.start();
        var ex = Executors.newFixedThreadPool(2);
        ex.submit(() -> copy(p.getInputStream(), stdout));
        ex.submit(() -> copy(p.getErrorStream(), stderr));
        // Планируется, что вызывающая сторона будет ждать p.waitFor() при необходимости
        return p;
    }

    private static void copy(InputStream is, Consumer<String> consumer) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (consumer != null) consumer.accept(line);
            }
        } catch (IOException ignored) {}
    }
}
