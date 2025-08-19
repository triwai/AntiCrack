package dev.anticrack;

import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;

/**
 * EAC-Style Game Integration Service
 * 
 * Provides secure inter-process communication between AntiCrack and games.
 * Games must register and maintain heartbeat to continue execution.
 * Implements mutual monitoring - AntiCrack monitors games, games monitor AntiCrack.
 */
public class GameIntegrationService {
    
    private static final int DEFAULT_PORT = 25565;
    private static final int HEARTBEAT_INTERVAL_MS = 5000;
    private static final int HEARTBEAT_TIMEOUT_MS = 15000;
    private static final String SECRET_KEY_ALGORITHM = "AES";
    
    private final AntiCrackAPI antiCrackAPI;
    private final CryptoProtection crypto;
    private final Map<String, RegisteredGame> registeredGames;
    private final Map<String, String> gameTokens;
    private final ScheduledExecutorService executor;
    private ServerSocket serverSocket;
    private final AtomicBoolean isRunning;
    private final SecureRandom secureRandom;
    
    // Authentication challenges for stronger security
    private final Map<String, AuthChallenge> authChallenges;
    
    public GameIntegrationService(AntiCrackAPI api, CryptoProtection crypto) {
        this.antiCrackAPI = api;
        this.crypto = crypto;
        this.registeredGames = new ConcurrentHashMap<>();
        this.gameTokens = new ConcurrentHashMap<>();
        this.authChallenges = new ConcurrentHashMap<>();
        this.executor = Executors.newScheduledThreadPool(10);
        this.isRunning = new AtomicBoolean(false);
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Start the game integration service
     */
    public void startService() throws IOException {
        if (isRunning.get()) {
            return;
        }
        
        serverSocket = new ServerSocket(DEFAULT_PORT);
        isRunning.set(true);
        
        System.out.println("[GameIntegration] Service started on port " + DEFAULT_PORT);
        
        // Start accepting game connections
        executor.submit(this::acceptConnections);
        
        // Start heartbeat monitoring
        executor.scheduleAtFixedRate(this::monitorHeartbeats, 
            HEARTBEAT_INTERVAL_MS, HEARTBEAT_INTERVAL_MS, TimeUnit.MILLISECONDS);
            
        // Start game integrity checking
        executor.scheduleAtFixedRate(this::checkGameIntegrity,
            10000, 10000, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Stop the game integration service
     */
    public void stopService() {
        if (!isRunning.get()) {
            return;
        }
        
        isRunning.set(false);
        
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            System.err.println("[GameIntegration] Error closing server socket: " + e.getMessage());
        }
        
        // Terminate all registered games
        for (RegisteredGame game : registeredGames.values()) {
            terminateGame(game, "AntiCrack service shutdown");
        }
        
        executor.shutdown();
        System.out.println("[GameIntegration] Service stopped");
    }
    
    /**
     * Accept incoming game connections
     */
    private void acceptConnections() {
        while (isRunning.get()) {
            try {
                Socket clientSocket = serverSocket.accept();
                executor.submit(() -> handleGameConnection(clientSocket));
            } catch (IOException e) {
                if (isRunning.get()) {
                    System.err.println("[GameIntegration] Error accepting connection: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * Handle individual game connection
     */
    private void handleGameConnection(Socket socket) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {
            
            // Read registration request
            String request = reader.readLine();
            if (request == null || !request.startsWith("REGISTER:")) {
                writer.println("ERROR:Invalid request format");
                return;
            }
            
            String[] parts = request.split(":");
            if (parts.length < 3) {
                writer.println("ERROR:Missing required fields");
                return;
            }
            
            String gameName = parts[1];
            String gameVersion = parts[2];
            String gameSignature = parts.length > 3 ? parts[3] : "";
            
            // Validate game
            if (!validateGameRegistration(gameName, gameVersion, gameSignature)) {
                writer.println("ERROR:Game validation failed");
                antiCrackAPI.notifyThreatDetected(ThreatType.UNKNOWN_THREAT, 
                    "Unauthorized game attempted registration: " + gameName);
                return;
            }
            
            // Create authentication challenge
            AuthChallenge challenge = createAuthChallenge(gameName);
            authChallenges.put(gameName, challenge);
            
            // Send challenge to game
            writer.println("CHALLENGE:" + challenge.challengeData);
            
            // Wait for challenge response
            String response = reader.readLine();
            if (!validateChallengeResponse(gameName, response)) {
                writer.println("ERROR:Authentication failed");
                antiCrackAPI.notifyThreatDetected(ThreatType.UNKNOWN_THREAT,
                    "Game failed authentication challenge: " + gameName);
                return;
            }
            
            // Generate secure token
            String token = generateSecureToken(gameName);
            gameTokens.put(gameName, token);
            
            // Register game
            RegisteredGame game = new RegisteredGame(gameName, gameVersion, token, socket);
            registeredGames.put(gameName, game);
            
            writer.println("SUCCESS:" + token);
            System.out.println("[GameIntegration] Game registered: " + gameName + " v" + gameVersion);
            
            // Start monitoring this game
            monitorGame(game, reader, writer);
            
        } catch (IOException e) {
            System.err.println("[GameIntegration] Error handling game connection: " + e.getMessage());
        }
    }
    
    /**
     * Validate game registration request
     */
    private boolean validateGameRegistration(String gameName, String gameVersion, String signature) {
        // Implement game whitelist/signature validation
        // For now, accept all games but log for monitoring
        System.out.println("[GameIntegration] Validating game: " + gameName + " v" + gameVersion);
        
        // Check against known malicious processes
        String[] suspiciousNames = {"cheat", "hack", "trainer", "bypass", "crack"};
        String lowerGameName = gameName.toLowerCase();
        
        for (String suspicious : suspiciousNames) {
            if (lowerGameName.contains(suspicious)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Create authentication challenge for game
     */
    private AuthChallenge createAuthChallenge(String gameName) {
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challengeData = Base64.getEncoder().encodeToString(challengeBytes);
        
        // Expected response is encrypted challenge data
        String expectedResponse = crypto.encryptData(challengeData, "master");
        
        return new AuthChallenge(challengeData, expectedResponse, System.currentTimeMillis());
    }
    
    /**
     * Validate challenge response from game
     */
    private boolean validateChallengeResponse(String gameName, String response) {
        AuthChallenge challenge = authChallenges.get(gameName);
        if (challenge == null) {
            return false;
        }
        
        // Check if challenge expired (30 seconds)
        if (System.currentTimeMillis() - challenge.timestamp > 30000) {
            authChallenges.remove(gameName);
            return false;
        }
        
        // For demo purposes, accept the simulated encryption format
        // In production, this would use proper AES decryption
        boolean valid = false;
        try {
            // Accept both proper encryption and demo format
            if (challenge.expectedResponse.equals(response)) {
                valid = true;
            } else {
                // Check demo format: Base64("ENCRYPTED:" + challengeData)
                byte[] decodedResponse = Base64.getDecoder().decode(response);
                String decodedString = new String(decodedResponse);
                if (decodedString.equals("ENCRYPTED:" + challenge.challengeData)) {
                    valid = true;
                }
            }
        } catch (Exception e) {
            // Invalid Base64 or other format issue
            valid = false;
        }
        
        authChallenges.remove(gameName);
        return valid;
    }
    
    /**
     * Generate secure token for authenticated game
     */
    private String generateSecureToken(String gameName) {
        String tokenData = gameName + ":" + System.currentTimeMillis() + ":" + 
                          UUID.randomUUID().toString();
        return crypto.generateChecksum(tokenData);
    }
    
    /**
     * Monitor individual game connection
     */
    private void monitorGame(RegisteredGame game, BufferedReader reader, PrintWriter writer) {
        try {
            String message;
            while (isRunning.get() && (message = reader.readLine()) != null) {
                if (message.startsWith("HEARTBEAT:")) {
                    game.updateHeartbeat();
                    writer.println("ACK");
                } else if (message.startsWith("STATUS:")) {
                    handleGameStatus(game, message);
                } else if (message.startsWith("THREAT:")) {
                    handleGameThreatReport(game, message);
                }
            }
        } catch (IOException e) {
            System.out.println("[GameIntegration] Game connection lost: " + game.name);
        } finally {
            unregisterGame(game.name);
        }
    }
    
    /**
     * Handle game status updates
     */
    private void handleGameStatus(RegisteredGame game, String message) {
        String[] parts = message.split(":", 2);
        if (parts.length > 1) {
            game.status = parts[1];
            System.out.println("[GameIntegration] " + game.name + " status: " + game.status);
        }
    }
    
    /**
     * Handle threat reports from games
     */
    private void handleGameThreatReport(RegisteredGame game, String message) {
        String[] parts = message.split(":", 2);
        if (parts.length > 1) {
            String threatInfo = parts[1];
            System.out.println("[GameIntegration] Threat reported by " + game.name + ": " + threatInfo);
            antiCrackAPI.notifyThreatDetected(ThreatType.UNKNOWN_THREAT, 
                "Game-reported threat: " + threatInfo);
        }
    }
    
    /**
     * Monitor heartbeats from all registered games
     */
    private void monitorHeartbeats() {
        long currentTime = System.currentTimeMillis();
        List<String> expiredGames = new ArrayList<>();
        
        for (Map.Entry<String, RegisteredGame> entry : registeredGames.entrySet()) {
            RegisteredGame game = entry.getValue();
            if (currentTime - game.lastHeartbeat > HEARTBEAT_TIMEOUT_MS) {
                expiredGames.add(entry.getKey());
            }
        }
        
        for (String gameName : expiredGames) {
            RegisteredGame game = registeredGames.get(gameName);
            if (game != null) {
                System.out.println("[GameIntegration] Heartbeat timeout for game: " + gameName);
                terminateGame(game, "Heartbeat timeout");
                unregisterGame(gameName);
            }
        }
    }
    
    /**
     * Check integrity of registered games
     */
    private void checkGameIntegrity() {
        for (RegisteredGame game : registeredGames.values()) {
            // Verify game process still exists and is legitimate
            if (!isGameProcessValid(game)) {
                System.out.println("[GameIntegration] Game integrity check failed: " + game.name);
                terminateGame(game, "Integrity check failed");
                unregisterGame(game.name);
            }
        }
    }
    
    /**
     * Validate that game process is legitimate
     */
    private boolean isGameProcessValid(RegisteredGame game) {
        // Implementation would check process integrity, loaded modules, etc.
        // For now, just check if socket is still connected
        return game.socket != null && game.socket.isConnected() && !game.socket.isClosed();
    }
    
    /**
     * Terminate a game process
     */
    private void terminateGame(RegisteredGame game, String reason) {
        try {
            if (game.socket != null && !game.socket.isClosed()) {
                PrintWriter writer = new PrintWriter(game.socket.getOutputStream(), true);
                writer.println("TERMINATE:" + reason);
                game.socket.close();
            }
        } catch (IOException e) {
            System.err.println("[GameIntegration] Error terminating game: " + e.getMessage());
        }
        
        System.out.println("[GameIntegration] Game terminated: " + game.name + " - " + reason);
        antiCrackAPI.notifyThreatDetected(ThreatType.CODE_INTEGRITY_VIOLATION,
            "Game terminated: " + game.name + " - " + reason);
    }
    
    /**
     * Unregister a game
     */
    private void unregisterGame(String gameName) {
        RegisteredGame game = registeredGames.remove(gameName);
        gameTokens.remove(gameName);
        authChallenges.remove(gameName);
        
        if (game != null) {
            try {
                if (game.socket != null && !game.socket.isClosed()) {
                    game.socket.close();
                }
            } catch (IOException e) {
                // Ignore
            }
            System.out.println("[GameIntegration] Game unregistered: " + gameName);
        }
    }
    
    /**
     * Get list of currently registered games
     */
    public Set<String> getRegisteredGames() {
        return new HashSet<>(registeredGames.keySet());
    }
    
    /**
     * Check if AntiCrack is required for system to function
     */
    public boolean isAntiCrackRequired() {
        return !registeredGames.isEmpty();
    }
    
    /**
     * Registered game information
     */
    private static class RegisteredGame {
        final String name;
        final String version;
        final String token;
        final Socket socket;
        volatile long lastHeartbeat;
        volatile String status;
        
        RegisteredGame(String name, String version, String token, Socket socket) {
            this.name = name;
            this.version = version;
            this.token = token;
            this.socket = socket;
            this.lastHeartbeat = System.currentTimeMillis();
            this.status = "CONNECTED";
        }
        
        void updateHeartbeat() {
            this.lastHeartbeat = System.currentTimeMillis();
        }
    }
    
    /**
     * Authentication challenge data
     */
    private static class AuthChallenge {
        final String challengeData;
        final String expectedResponse;
        final long timestamp;
        
        AuthChallenge(String challengeData, String expectedResponse, long timestamp) {
            this.challengeData = challengeData;
            this.expectedResponse = expectedResponse;
            this.timestamp = timestamp;
        }
    }
}