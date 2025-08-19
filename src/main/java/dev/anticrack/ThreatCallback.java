package dev.anticrack;

/**
 * Callback interface for handling threat detection notifications
 * 
 * External software should implement this interface to receive
 * notifications when AntiCrack detects security threats.
 */
@FunctionalInterface
public interface ThreatCallback {
    
    /**
     * Called when a security threat is detected
     * 
     * @param type The type of threat that was detected
     * @param description Detailed description of the threat
     */
    void onThreatDetected(ThreatType type, String description);
    
    /**
     * Default implementation that can be extended for additional threat response
     * 
     * @param type The type of threat that was detected
     * @param description Detailed description of the threat
     * @param severity Severity level of the threat (1-10, where 10 is critical)
     */
    default void onThreatDetected(ThreatType type, String description, int severity) {
        onThreatDetected(type, description);
    }
    
    /**
     * Called when a threat has been successfully mitigated
     * 
     * @param type The type of threat that was mitigated
     * @param description Description of the mitigation action taken
     */
    default void onThreatMitigated(ThreatType type, String description) {
        // Default implementation does nothing
        // External software can override to handle mitigation notifications
    }
}