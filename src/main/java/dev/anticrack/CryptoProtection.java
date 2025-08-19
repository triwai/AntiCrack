package dev.anticrack;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Cryptographic protection mechanisms for AntiCrack
 * 
 * Provides code obfuscation, runtime encryption, and key management
 * to make reverse engineering significantly more difficult.
 */
public class CryptoProtection {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_LENGTH = 256;
    private static final int IV_LENGTH = 16;
    
    private final SecureRandom secureRandom;
    private final Map<String, SecretKey> keyStore;
    private final AntiCrackAPI api;
    
    public CryptoProtection(AntiCrackAPI api) {
        this.api = api;
        this.secureRandom = new SecureRandom();
        this.keyStore = new ConcurrentHashMap<>();
        initializeKeys();
    }
    
    /**
     * Initialize encryption keys for different protection levels
     */
    private void initializeKeys() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(KEY_LENGTH, secureRandom);
            
            // Generate keys for different protection components
            keyStore.put("MEMORY_PROTECTION", keyGenerator.generateKey());
            keyStore.put("CODE_INTEGRITY", keyGenerator.generateKey());
            keyStore.put("API_OBFUSCATION", keyGenerator.generateKey());
            keyStore.put("RUNTIME_ENCRYPTION", keyGenerator.generateKey());
            
            System.out.println("[CryptoProtection] Encryption keys initialized");
        } catch (Exception e) {
            System.err.println("[CryptoProtection] Failed to initialize keys: " + e.getMessage());
            api.notifyThreatDetected(ThreatType.CODE_INTEGRITY_VIOLATION, 
                "Encryption key initialization failed - possible tampering");
        }
    }
    
    /**
     * Encrypt sensitive data using AES encryption
     * @param data Data to encrypt
     * @param keyName Name of the key to use
     * @return Encrypted data as Base64 string, or null if encryption fails
     */
    public String encryptData(String data, String keyName) {
        try {
            SecretKey key = keyStore.get(keyName);
            if (key == null) {
                throw new IllegalArgumentException("Key not found: " + keyName);
            }
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            
            // Generate random IV
            byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            
            // Combine IV and encrypted data
            byte[] combined = new byte[IV_LENGTH + encryptedData.length];
            System.arraycopy(iv, 0, combined, 0, IV_LENGTH);
            System.arraycopy(encryptedData, 0, combined, IV_LENGTH, encryptedData.length);
            
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            System.err.println("[CryptoProtection] Encryption failed: " + e.getMessage());
            api.notifyThreatDetected(ThreatType.CODE_INTEGRITY_VIOLATION, 
                "Data encryption failed - possible tampering");
            return null;
        }
    }
    
    /**
     * Decrypt sensitive data using AES encryption
     * @param encryptedData Base64 encoded encrypted data
     * @param keyName Name of the key to use
     * @return Decrypted data, or null if decryption fails
     */
    public String decryptData(String encryptedData, String keyName) {
        try {
            SecretKey key = keyStore.get(keyName);
            if (key == null) {
                throw new IllegalArgumentException("Key not found: " + keyName);
            }
            
            byte[] combined = Base64.getDecoder().decode(encryptedData);
            
            // Extract IV and encrypted data
            byte[] iv = new byte[IV_LENGTH];
            byte[] encrypted = new byte[combined.length - IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
            System.arraycopy(combined, IV_LENGTH, encrypted, 0, encrypted.length);
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            
            byte[] decryptedData = cipher.doFinal(encrypted);
            return new String(decryptedData);
        } catch (Exception e) {
            System.err.println("[CryptoProtection] Decryption failed: " + e.getMessage());
            api.notifyThreatDetected(ThreatType.CODE_INTEGRITY_VIOLATION, 
                "Data decryption failed - possible tampering or wrong key");
            return null;
        }
    }
    
    /**
     * Generate a checksum for code integrity verification
     * @param data Data to generate checksum for
     * @return Base64 encoded checksum
     */
    public String generateChecksum(String data) {
        try {
            // Simple checksum using encrypted hash
            String encrypted = encryptData(data, "CODE_INTEGRITY");
            if (encrypted != null) {
                // Return first 32 characters as checksum
                return encrypted.substring(0, Math.min(32, encrypted.length()));
            }
            return null;
        } catch (Exception e) {
            System.err.println("[CryptoProtection] Checksum generation failed: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Verify code integrity using checksum
     * @param data Original data
     * @param expectedChecksum Expected checksum
     * @return true if integrity is verified, false otherwise
     */
    public boolean verifyIntegrity(String data, String expectedChecksum) {
        String actualChecksum = generateChecksum(data);
        boolean isValid = actualChecksum != null && actualChecksum.equals(expectedChecksum);
        
        if (!isValid) {
            api.notifyThreatDetected(ThreatType.CODE_INTEGRITY_VIOLATION, 
                "Code integrity verification failed - code may have been modified");
        }
        
        return isValid;
    }
    
    /**
     * Obfuscate a string using simple encryption
     * @param input String to obfuscate
     * @return Obfuscated string
     */
    public String obfuscateString(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        
        try {
            // XOR obfuscation with random key
            byte[] key = new byte[input.length()];
            secureRandom.nextBytes(key);
            
            byte[] inputBytes = input.getBytes();
            byte[] obfuscated = new byte[inputBytes.length];
            
            for (int i = 0; i < inputBytes.length; i++) {
                obfuscated[i] = (byte) (inputBytes[i] ^ key[i]);
            }
            
            // Combine key and obfuscated data
            byte[] combined = new byte[key.length + obfuscated.length];
            System.arraycopy(key, 0, combined, 0, key.length);
            System.arraycopy(obfuscated, 0, combined, key.length, obfuscated.length);
            
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            System.err.println("[CryptoProtection] String obfuscation failed: " + e.getMessage());
            return input; // Return original if obfuscation fails
        }
    }
    
    /**
     * Deobfuscate a string that was obfuscated using obfuscateString
     * @param obfuscatedInput Obfuscated string
     * @return Original string
     */
    public String deobfuscateString(String obfuscatedInput) {
        if (obfuscatedInput == null || obfuscatedInput.isEmpty()) {
            return obfuscatedInput;
        }
        
        try {
            byte[] combined = Base64.getDecoder().decode(obfuscatedInput);
            int halfLength = combined.length / 2;
            
            // Extract key and obfuscated data
            byte[] key = new byte[halfLength];
            byte[] obfuscated = new byte[halfLength];
            System.arraycopy(combined, 0, key, 0, halfLength);
            System.arraycopy(combined, halfLength, obfuscated, 0, halfLength);
            
            // XOR deobfuscation
            byte[] original = new byte[obfuscated.length];
            for (int i = 0; i < obfuscated.length; i++) {
                original[i] = (byte) (obfuscated[i] ^ key[i]);
            }
            
            return new String(original);
        } catch (Exception e) {
            System.err.println("[CryptoProtection] String deobfuscation failed: " + e.getMessage());
            return obfuscatedInput; // Return obfuscated if deobfuscation fails
        }
    }
    
    /**
     * Generate a runtime token for session validation
     * @return Base64 encoded runtime token
     */
    public String generateRuntimeToken() {
        try {
            // Generate a unique token based on current time and random data
            long timestamp = System.currentTimeMillis();
            byte[] randomBytes = new byte[16];
            secureRandom.nextBytes(randomBytes);
            
            String tokenData = timestamp + ":" + Base64.getEncoder().encodeToString(randomBytes);
            return encryptData(tokenData, "RUNTIME_ENCRYPTION");
        } catch (Exception e) {
            System.err.println("[CryptoProtection] Runtime token generation failed: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Validate a runtime token
     * @param token Token to validate
     * @return true if token is valid and not expired, false otherwise
     */
    public boolean validateRuntimeToken(String token) {
        try {
            String decryptedToken = decryptData(token, "RUNTIME_ENCRYPTION");
            if (decryptedToken == null) {
                return false;
            }
            
            String[] parts = decryptedToken.split(":");
            if (parts.length != 2) {
                return false;
            }
            
            long timestamp = Long.parseLong(parts[0]);
            long currentTime = System.currentTimeMillis();
            
            // Token expires after 1 hour (3600000 milliseconds)
            long expirationTime = 3600000;
            return (currentTime - timestamp) < expirationTime;
        } catch (Exception e) {
            System.err.println("[CryptoProtection] Runtime token validation failed: " + e.getMessage());
            api.notifyThreatDetected(ThreatType.CODE_INTEGRITY_VIOLATION, 
                "Runtime token validation failed - possible tampering");
            return false;
        }
    }
    
    /**
     * Securely wipe keys from memory (best effort)
     */
    public void wipeKeys() {
        try {
            keyStore.clear();
            System.gc(); // Suggest garbage collection
            System.out.println("[CryptoProtection] Encryption keys wiped from memory");
        } catch (Exception e) {
            System.err.println("[CryptoProtection] Failed to wipe keys: " + e.getMessage());
        }
    }
}