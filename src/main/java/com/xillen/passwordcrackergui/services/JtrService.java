package com.xillen.passwordcrackergui.services;

public class JtrService {
    public String buildCommand(String type, String method, String targetPath,
                               String dict, String mask, String rainbow) {
        String base = "john"; // Assumes john in PATH; to be integrated properly
        StringBuilder sb = new StringBuilder(base).append(" ");
        if (method != null) {
            switch (method) {
                case "Dictionary", "Словарь" -> sb.append("--wordlist=\"").append(dict).append("\" ");
                case "Mask", "Маска" -> sb.append("--mask=\"").append(mask).append("\" ");
                case "Rainbow Table", "Радужные таблицы" -> sb.append("--format=rainbow --tables=\"").append(rainbow).append("\" ");
                default -> {}
            }
        }
        // Target type can adjust format
        if ("ZIP".equals(type)) sb.append("--format=zip ");
        if ("PDF".equals(type)) sb.append("--format=pdf ");
        if ("RDP".equals(type)) sb.append("--format=NT ");
        if ("WiFi".equals(type)) sb.append("--format=wpapsk ");
        sb.append('\'').append(targetPath).append('\'');
        return sb.toString();
    }
}
