package dev.anticrack;

/**
 * Enumeration of different types of security threats that AntiCrack can detect
 */
public enum ThreatType {
    
    /** Debugger attachment detected */
    DEBUGGER_DETECTED("Debugger or debugging tool detected"),
    
    /** Memory patching or code modification detected */
    MEMORY_PATCHING("Memory patching or code modification detected"),
    
    /** Process injection detected */
    PROCESS_INJECTION("Process injection or DLL injection detected"),
    
    /** Virtual machine environment detected */
    VIRTUAL_MACHINE("Virtual machine environment detected"),
    
    /** API hooking detected */
    API_HOOKING("API hooking or function interception detected"),
    
    /** Hardware breakpoint detected */
    HARDWARE_BREAKPOINT("Hardware breakpoint detected"),
    
    /** Timing anomaly suggesting debugging */
    TIMING_ANOMALY("Timing anomaly suggesting debugging activity"),
    
    /** Code integrity violation */
    CODE_INTEGRITY_VIOLATION("Code integrity check failed"),
    
    /** Unknown or generic threat */
    UNKNOWN_THREAT("Unknown or unclassified threat detected");
    
    private final String description;
    
    ThreatType(String description) {
        this.description = description;
    }
    
    public String getDescription() {
        return description;
    }
    
    @Override
    public String toString() {
        return name() + ": " + description;
    }
}