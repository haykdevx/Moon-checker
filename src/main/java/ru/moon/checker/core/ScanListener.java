package ru.moon.checker.core;

/**
 * Callbacks the UI implements to render a scan live. All methods may be called
 * from worker threads, so implementations must marshal to the EDT themselves.
 * A no-op default is provided for each so tests can implement only what they
 * need.
 */
public interface ScanListener {

    default void onScanStart(int totalModules) {
    }

    default void onModuleStart(CheckModule module) {
    }

    default void onModuleDone(CheckModule module, ModuleStatus status, int findingCount) {
    }

    /** A single new finding, as it is discovered. */
    default void onFinding(Finding finding) {
    }

    /** A line for the live "currently scanning..." log. */
    default void onLog(String line) {
    }

    default void onComplete(ScanResult result) {
    }

    ScanListener NOOP = new ScanListener() {
    };
}
