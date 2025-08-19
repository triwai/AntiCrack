package dev.anticrack;

/**
 * Enumeration of protection levels that can be configured for AntiCrack
 * 
 * Different protection levels provide varying degrees of security vs performance trade-offs
 */
public enum ProtectionLevel {
    
    /** 
     * Minimal protection - Basic threat detection only
     * Low performance impact, suitable for performance-critical applications
     */
    LOW(1, "Minimal Protection", "Basic threat detection with minimal performance impact"),
    
    /** 
     * Moderate protection - Standard threat detection and some active protection
     * Balanced security and performance
     */
    MEDIUM(2, "Moderate Protection", "Standard threat detection with balanced security/performance"),
    
    /** 
     * High protection - Comprehensive threat detection and active protection
     * Higher performance impact but strong security
     */
    HIGH(3, "High Protection", "Comprehensive threat detection and active protection measures"),
    
    /** 
     * Maximum protection - All available protection mechanisms enabled
     * Highest security but significant performance impact
     */
    MAXIMUM(4, "Maximum Protection", "All protection mechanisms enabled - highest security level"),
    
    /** 
     * Custom protection - User-defined protection configuration
     * Allows fine-tuning of individual protection components
     */
    CUSTOM(5, "Custom Protection", "User-defined protection configuration");
    
    private final int level;
    private final String name;
    private final String description;
    
    ProtectionLevel(int level, String name, String description) {
        this.level = level;
        this.name = name;
        this.description = description;
    }
    
    /**
     * Get the numeric protection level
     * @return Protection level as integer (1-5)
     */
    public int getLevel() {
        return level;
    }
    
    /**
     * Get the human-readable name of this protection level
     * @return Protection level name
     */
    public String getName() {
        return name;
    }
    
    /**
     * Get the description of this protection level
     * @return Protection level description
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Check if this protection level includes debugger detection
     * @return true if debugger detection is enabled at this level
     */
    public boolean includesDebuggerDetection() {
        return level >= LOW.level;
    }
    
    /**
     * Check if this protection level includes memory protection
     * @return true if memory protection is enabled at this level
     */
    public boolean includesMemoryProtection() {
        return level >= MEDIUM.level;
    }
    
    /**
     * Check if this protection level includes active countermeasures
     * @return true if active countermeasures are enabled at this level
     */
    public boolean includesActiveCountermeasures() {
        return level >= HIGH.level;
    }
    
    /**
     * Check if this protection level includes advanced obfuscation
     * @return true if advanced obfuscation is enabled at this level
     */
    public boolean includesAdvancedObfuscation() {
        return level >= MAXIMUM.level;
    }
    
    @Override
    public String toString() {
        return name + " (Level " + level + "): " + description;
    }
}