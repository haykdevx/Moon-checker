package ru.moon.checker.checks;

/** Test access to KernelCheck's package-private helpers from other test packages. */
public final class KernelCheckAccess {
    private KernelCheckAccess() {
    }

    public static boolean system(String path) {
        return KernelCheck.systemDriverPath(path);
    }
}
