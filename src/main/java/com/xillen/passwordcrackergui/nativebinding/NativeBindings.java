package com.xillen.passwordcrackergui.nativebinding;

public class NativeBindings {
    static {
        // Try to load native library named "pwcrack"
        try {
            System.loadLibrary("pwcrack");
        } catch (Throwable ignored) {}
    }

    // Использование JNI для нативного кода
    public static native String crackZipNative(String path, String charset);
}
