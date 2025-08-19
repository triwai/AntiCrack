package dev.anticrack.examples;

import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Sample Game Client demonstrating AntiCrack integration
 * 
 * This example shows how games should integrate with the AntiCrack system:
 * 1. Check if AntiCrack is running before starting
 * 2. Register with AntiCrack service
 * 3. Authenticate using challenge-response
 * 4. Maintain heartbeat communication
 * 5. Monitor AntiCrack availability
 * 6. Terminate if AntiCrack connection is lost
 */
public class SampleGameClient {
    
    private static final String GAME_NAME = "SampleGame";
    private static final String GAME_VERSION = "1.0.0";
    private static final String ANTICRACK_HOST = "localhost";
    private static final int ANTICRACK_PORT = 25565;
    private static final int HEARTBEAT_INTERVAL_MS = 4000; // Slightly faster than server timeout
    
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private final AtomicBoolean connected = new AtomicBoolean(false);
    private final AtomicBoolean gameRunning = new AtomicBoolean(false);
    private final ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);
    private String authToken;
    
    public static void main(String[] args) {
        System.out.println("=== Sample Game with AntiCrack Integration ===");
        
        SampleGameClient game = new SampleGameClient();
        
        try {
            // Step 1: Check AntiCrack availability
            if (!game.checkAntiCrackAvailability()) {
                System.err.println("[GAME] AntiCrack protection system is not running!");
                System.err.println("[GAME] This game requires AntiCrack to be active for security.");
                System.err.println("[GAME] Please start AntiCrack before launching this game.");
                System.exit(1);
            }
            
            // Step 2: Register with AntiCrack
            if (!game.registerWithAntiCrack()) {
                System.err.println("[GAME] Failed to register with AntiCrack protection system!");
                System.exit(1);
            }
            
            // Step 3: Start game main loop
            game.startGame();
            
        } catch (Exception e) {
            System.err.println("[GAME] Fatal error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            game.shutdown();
        }
    }
    
    /**
     * Check if AntiCrack service is available
     */
    private boolean checkAntiCrackAvailability() {
        try (Socket testSocket = new Socket()) {
            testSocket.connect(new InetSocketAddress(ANTICRACK_HOST, ANTICRACK_PORT), 5000);
            System.out.println("[GAME] AntiCrack service detected and available");
            return true;
        } catch (IOException e) {
            System.out.println("[GAME] AntiCrack service not available: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Register with AntiCrack service
     */
    private boolean registerWithAntiCrack() {
        try {
            // Connect to AntiCrack service
            socket = new Socket(ANTICRACK_HOST, ANTICRACK_PORT);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new PrintWriter(socket.getOutputStream(), true);
            
            System.out.println("[GAME] Connected to AntiCrack service");
            
            // Send registration request
            String registrationRequest = "REGISTER:" + GAME_NAME + ":" + GAME_VERSION + ":DEMO_SIGNATURE";
            writer.println(registrationRequest);
            System.out.println("[GAME] Sent registration request: " + registrationRequest);
            
            // Wait for response
            String response = reader.readLine();
            if (response == null) {
                System.err.println("[GAME] No response from AntiCrack service");
                return false;
            }
            
            System.out.println("[GAME] Received response: " + response);
            
            if (response.startsWith("ERROR:")) {
                System.err.println("[GAME] Registration failed: " + response.substring(6));
                return false;
            }
            
            if (response.startsWith("CHALLENGE:")) {
                // Handle authentication challenge
                String challengeData = response.substring(10);
                return handleAuthenticationChallenge(challengeData);
            }
            
            System.err.println("[GAME] Unexpected response format: " + response);
            return false;
            
        } catch (IOException e) {
            System.err.println("[GAME] Error connecting to AntiCrack: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Handle authentication challenge from AntiCrack
     */
    private boolean handleAuthenticationChallenge(String challengeData) {
        try {
            System.out.println("[GAME] Received authentication challenge");
            
            // In a real implementation, this would use the same encryption key as AntiCrack
            // For demo purposes, we'll simulate the correct response
            String challengeResponse = simulateEncryption(challengeData);
            
            // Send challenge response
            writer.println(challengeResponse);
            System.out.println("[GAME] Sent challenge response");
            
            // Wait for final authentication result
            String authResult = reader.readLine();
            if (authResult == null) {
                System.err.println("[GAME] No authentication result received");
                return false;
            }
            
            System.out.println("[GAME] Authentication result: " + authResult);
            
            if (authResult.startsWith("SUCCESS:")) {
                authToken = authResult.substring(8);
                connected.set(true);
                System.out.println("[GAME] Successfully authenticated with AntiCrack!");
                System.out.println("[GAME] Received auth token: " + authToken.substring(0, 10) + "...");
                
                // Start monitoring connection
                startConnectionMonitoring();
                startHeartbeat();
                
                return true;
            } else if (authResult.startsWith("ERROR:")) {
                System.err.println("[GAME] Authentication failed: " + authResult.substring(6));
                return false;
            }
            
            System.err.println("[GAME] Unexpected authentication result: " + authResult);
            return false;
            
        } catch (IOException e) {
            System.err.println("[GAME] Error during authentication: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Simulate encryption for demo purposes
     * In a real implementation, this would use the same CryptoProtection as AntiCrack
     */
    private String simulateEncryption(String data) {
        // For demo purposes, we'll use simple Base64 encoding
        // In reality, this should use the same AES encryption as AntiCrack
        try {
            return Base64.getEncoder().encodeToString(("ENCRYPTED:" + data).getBytes());
        } catch (Exception e) {
            return data; // Fallback for demo
        }
    }
    
    /**
     * Start heartbeat communication with AntiCrack
     */
    private void startHeartbeat() {
        executor.scheduleAtFixedRate(() -> {
            if (connected.get() && gameRunning.get()) {
                try {
                    writer.println("HEARTBEAT:" + System.currentTimeMillis());
                    // Don't wait for ACK in this thread to avoid blocking
                } catch (Exception e) {
                    System.err.println("[GAME] Error sending heartbeat: " + e.getMessage());
                    handleConnectionLost();
                }
            }
        }, 1000, HEARTBEAT_INTERVAL_MS, TimeUnit.MILLISECONDS);
        
        System.out.println("[GAME] Heartbeat started (interval: " + HEARTBEAT_INTERVAL_MS + "ms)");
    }
    
    /**
     * Start monitoring connection to AntiCrack
     */
    private void startConnectionMonitoring() {
        executor.submit(() -> {
            try {
                String message;
                while (connected.get() && (message = reader.readLine()) != null) {
                    handleAntiCrackMessage(message);
                }
            } catch (IOException e) {
                if (connected.get()) {
                    System.err.println("[GAME] Connection to AntiCrack lost: " + e.getMessage());
                    handleConnectionLost();
                }
            }
        });
    }
    
    /**
     * Handle messages from AntiCrack
     */
    private void handleAntiCrackMessage(String message) {
        if (message.equals("ACK")) {
            // Heartbeat acknowledged
            return;
        } else if (message.startsWith("TERMINATE:")) {
            String reason = message.substring(10);
            System.err.println("[GAME] AntiCrack requested termination: " + reason);
            System.err.println("[GAME] Game will now exit for security reasons.");
            handleForcedTermination(reason);
        } else {
            System.out.println("[GAME] Received from AntiCrack: " + message);
        }
    }
    
    /**
     * Handle connection lost to AntiCrack
     */
    private void handleConnectionLost() {
        connected.set(false);
        gameRunning.set(false);
        System.err.println("[GAME] Connection to AntiCrack protection system lost!");
        System.err.println("[GAME] Game cannot continue without AntiCrack protection.");
        System.err.println("[GAME] Terminating for security reasons...");
        
        // Give user a moment to see the message
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        System.exit(2);
    }
    
    /**
     * Handle forced termination by AntiCrack
     */
    private void handleForcedTermination(String reason) {
        connected.set(false);
        gameRunning.set(false);
        
        // Report the termination reason
        System.err.println("[GAME] SECURITY VIOLATION DETECTED!");
        System.err.println("[GAME] AntiCrack has detected a security threat: " + reason);
        System.err.println("[GAME] This game session is being terminated to protect against cheating.");
        
        // Give user time to read the message
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        System.exit(3);
    }
    
    /**
     * Start the game main loop
     */
    private void startGame() {
        gameRunning.set(true);
        System.out.println("\n[GAME] ===== GAME STARTED =====");
        System.out.println("[GAME] AntiCrack integration active");
        System.out.println("[GAME] Protected against:");
        System.out.println("[GAME] - Memory hacking");
        System.out.println("[GAME] - Process injection");
        System.out.println("[GAME] - Debugging attempts");
        System.out.println("[GAME] - Code tampering");
        System.out.println("[GAME] ============================\n");
        
        // Simulate game main loop
        try {
            for (int i = 0; i < 60; i++) { // Run for 60 seconds
                if (!gameRunning.get()) {
                    break;
                }
                
                // Simulate game activity
                Thread.sleep(1000);
                
                if (i % 10 == 0) {
                    System.out.println("[GAME] Game running... (" + (60-i) + " seconds remaining)");
                    
                    // Occasionally report status to AntiCrack
                    if (connected.get()) {
                        writer.println("STATUS:Running normally - Level " + (i/10 + 1));
                    }
                }
                
                // Simulate detecting a potential threat (for demo)
                if (i == 30) {
                    System.out.println("[GAME] Detected suspicious activity - reporting to AntiCrack");
                    if (connected.get()) {
                        writer.println("THREAT:Suspicious memory access pattern detected");
                    }
                }
            }
            
            System.out.println("\n[GAME] Game session completed successfully!");
            
        } catch (InterruptedException e) {
            System.out.println("[GAME] Game interrupted");
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Shutdown the game client
     */
    private void shutdown() {
        System.out.println("[GAME] Shutting down game client...");
        
        connected.set(false);
        gameRunning.set(false);
        
        executor.shutdown();
        
        try {
            if (writer != null) {
                writer.println("STATUS:Game shutting down normally");
                writer.close();
            }
            if (reader != null) {
                reader.close();
            }
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            // Ignore errors during shutdown
        }
        
        System.out.println("[GAME] Game client shutdown complete");
    }
}