package dev.anticrack;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.Map;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Main API interface for external software to integrate with AntiCrack protection system
 * 
 * This singleton class provides all the necessary methods for external applications
 * to configure and interact with AntiCrack's protection mechanisms.
 */
public class AntiCrackAPI {
    
    private static final AntiCrackAPI INSTANCE = new AntiCrackAPI();
    
    // Configuration
    private final AtomicReference<ProtectionLevel> protectionLevel = new AtomicReference<>(ProtectionLevel.MEDIUM);
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    
    // Callbacks and listeners
    private final List<ThreatCallback> threatCallbacks = new CopyOnWriteArrayList<>();
    
    // Statistics and monitoring
    private final Map<ThreatType, Integer> threatCounts = new ConcurrentHashMap<>();
    private final AtomicBoolean protectionActive = new AtomicBoolean(false);
    
    // Custom configuration for CUSTOM protection level
    private final Map<String, Object> customConfig = new ConcurrentHashMap<>();
    
    private AntiCrackAPI() {
        // Initialize threat counters
        for (ThreatType type : ThreatType.values()) {
            threatCounts.put(type, 0);
        }
    }
    
    /**
     * Get the singleton instance of AntiCrackAPI
     * @return The AntiCrackAPI instance
     */
    public static AntiCrackAPI getInstance() {
        return INSTANCE;
    }
    
    /**
     * Initialize the AntiCrack protection system
     * This must be called before using any other API methods
     * 
     * @return true if initialization was successful, false otherwise
     */
    public boolean initialize() {
        if (initialized.compareAndSet(false, true)) {
            System.out.println("[AntiCrackAPI] Initializing protection system...");
            protectionActive.set(true);
            System.out.println("[AntiCrackAPI] Protection system initialized successfully");
            return true;
        }
        System.out.println("[AntiCrackAPI] Protection system already initialized");
        return false;
    }
    
    /**
     * Shutdown the AntiCrack protection system
     */
    public void shutdown() {
        if (initialized.compareAndSet(true, false)) {
            System.out.println("[AntiCrackAPI] Shutting down protection system...");
            protectionActive.set(false);
            threatCallbacks.clear();
            System.out.println("[AntiCrackAPI] Protection system shutdown complete");
        }
    }
    
    /**
     * Set the protection level
     * @param level The protection level to use
     */
    public void setProtectionLevel(ProtectionLevel level) {
        if (level == null) {
            throw new IllegalArgumentException("Protection level cannot be null");
        }
        
        ProtectionLevel oldLevel = this.protectionLevel.getAndSet(level);
        System.out.println("[AntiCrackAPI] Protection level changed from " + oldLevel + " to " + level);
    }
    
    /**
     * Get the current protection level
     * @return The current protection level
     */
    public ProtectionLevel getProtectionLevel() {
        return protectionLevel.get();
    }
    
    /**
     * Add a threat detection callback
     * @param callback The callback to add
     */
    public void setThreatCallback(ThreatCallback callback) {
        if (callback == null) {
            throw new IllegalArgumentException("Threat callback cannot be null");
        }
        
        threatCallbacks.clear(); // Replace existing callbacks
        threatCallbacks.add(callback);
        System.out.println("[AntiCrackAPI] Threat callback registered");
    }
    
    /**
     * Add an additional threat detection callback (multiple callbacks supported)
     * @param callback The callback to add
     */
    public void addThreatCallback(ThreatCallback callback) {
        if (callback == null) {
            throw new IllegalArgumentException("Threat callback cannot be null");
        }
        
        threatCallbacks.add(callback);
        System.out.println("[AntiCrackAPI] Additional threat callback registered");
    }
    
    /**
     * Remove a threat detection callback
     * @param callback The callback to remove
     */
    public void removeThreatCallback(ThreatCallback callback) {
        threatCallbacks.remove(callback);
        System.out.println("[AntiCrackAPI] Threat callback removed");
    }
    
    /**
     * Notify all registered callbacks of a detected threat
     * @param type The type of threat detected
     * @param description Description of the threat
     */
    public void notifyThreatDetected(ThreatType type, String description) {
        // Update statistics
        threatCounts.merge(type, 1, Integer::sum);
        
        // Notify all callbacks
        for (ThreatCallback callback : threatCallbacks) {
            try {
                callback.onThreatDetected(type, description);
            } catch (Exception e) {
                System.err.println("[AntiCrackAPI] Error in threat callback: " + e.getMessage());
            }
        }
    }
    
    /**
     * Get threat detection statistics
     * @return Map of threat types to detection counts
     */
    public Map<ThreatType, Integer> getThreatStatistics() {
        return new ConcurrentHashMap<>(threatCounts);
    }
    
    /**
     * Check if protection is currently active
     * @return true if protection is active, false otherwise
     */
    public boolean isProtectionActive() {
        return protectionActive.get() && initialized.get();
    }
    
    /**
     * Force a manual threat scan
     * @return true if scan completed successfully, false otherwise
     */
    public boolean performManualScan() {
        if (!isProtectionActive()) {
            System.out.println("[AntiCrackAPI] Cannot perform scan - protection not active");
            return false;
        }
        
        System.out.println("[AntiCrackAPI] Performing manual threat scan...");
        // This will be implemented by the core AntiCrack class
        // For now, just simulate a scan
        System.out.println("[AntiCrackAPI] Manual scan completed");
        return true;
    }
    
    /**
     * Set custom configuration option (for CUSTOM protection level)
     * @param key Configuration key
     * @param value Configuration value
     */
    public void setCustomConfig(String key, Object value) {
        customConfig.put(key, value);
        System.out.println("[AntiCrackAPI] Custom config set: " + key + " = " + value);
    }
    
    /**
     * Get custom configuration option
     * @param key Configuration key
     * @return Configuration value, or null if not set
     */
    public Object getCustomConfig(String key) {
        return customConfig.get(key);
    }
    
    /**
     * Get version information
     * @return Version string
     */
    public String getVersion() {
        return "AntiCrack v1.0.0";
    }
    
    /**
     * Get status summary
     * @return Status information as string
     */
    public String getStatusSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("AntiCrack Status:\n");
        sb.append("  Initialized: ").append(initialized.get()).append("\n");
        sb.append("  Protection Active: ").append(protectionActive.get()).append("\n");
        sb.append("  Protection Level: ").append(protectionLevel.get().getName()).append("\n");
        sb.append("  Callbacks Registered: ").append(threatCallbacks.size()).append("\n");
        
        int totalThreats = threatCounts.values().stream().mapToInt(Integer::intValue).sum();
        sb.append("  Total Threats Detected: ").append(totalThreats);
        
        return sb.toString();
    }
}