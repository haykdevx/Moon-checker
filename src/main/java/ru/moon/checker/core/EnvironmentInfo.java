package ru.moon.checker.core;

import java.net.InetAddress;

/**
 * Machine / run metadata displayed in the header bar and the report so the
 * admin can confirm the live screen share matches a real, current run.
 *
 * @param hostname   PC name
 * @param osName     e.g. "Windows 11"
 * @param userName   logged-in Windows user
 * @param elevated   whether the app has administrator rights
 * @param appVersion checker version (from the manifest)
 * @param selfHash   short sha-256 prefix of the running jar/exe
 * @param jvm        java runtime string
 */
public record EnvironmentInfo(
        String hostname,
        String osName,
        String userName,
        boolean elevated,
        String appVersion,
        String selfHash,
        String jvm
) {
    public static EnvironmentInfo capture(boolean elevated, String appVersion, String selfHash) {
        String host;
        try {
            host = InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            String env = System.getenv("COMPUTERNAME");
            host = env != null ? env : "unknown";
        }
        String user = System.getProperty("user.name", System.getenv("USERNAME"));
        String jvm = System.getProperty("java.vendor", "?") + " " + System.getProperty("java.version", "?");
        return new EnvironmentInfo(host, Platform.osName(), user, elevated, appVersion, selfHash, jvm);
    }
}
