# AntiCrack - EAC-Style Anti-Cheat Protection System

**Languages / 言語**: [English](README.md) | [日本語](README_ja.md)

AntiCrack is an advanced anti-reverse engineering and anti-cheat protection system designed to provide EAC (Easy Anti-Cheat) level security for games and applications. It implements comprehensive protection against debugging, memory manipulation, code tampering, and other attack vectors commonly used by cheaters and crackers.

## 🛡️ Features

### Core Protection Mechanisms
- **Advanced Debugger Detection**: Multi-layered detection of debugging tools (x64dbg, OllyDbg, IDA Pro, etc.)
- **Memory Protection**: Real-time monitoring of memory modifications and code patching
- **Process Integrity**: Verification of loaded modules and process integrity
- **VM Detection**: Detection of virtual machine environments used for analysis
- **API Hooking Detection**: Protection against API interception and function hooking
- **Hardware Breakpoint Detection**: Detection of hardware-level debugging attempts
- **Timing Analysis**: Detection of debugging through timing anomalies

### EAC-Style Game Integration
- **Mandatory Protection**: Games cannot run without AntiCrack active
- **Secure Communication**: Encrypted challenge-response authentication
- **Mutual Monitoring**: Both AntiCrack and games monitor each other
- **Heartbeat System**: Continuous connection verification
- **Automatic Termination**: Games are terminated if protection is compromised
- **Threat Reporting**: Bi-directional threat information sharing

### Advanced Security Features
- **Cryptographic Protection**: AES encryption for sensitive operations
- **Runtime Token Validation**: Secure token-based authentication
- **Process Whitelisting**: Only authorized games can connect
- **Challenge-Response Auth**: Prevents unauthorized game registration
- **Connection Integrity**: Continuous monitoring of communication channels

## 🚀 Quick Start

### Prerequisites
- Java 8 or higher
- Gradle (for building from source)

### Running AntiCrack Protection System

1. **Start AntiCrack Service**:
   ```bash
   java -cp build/classes/java/main dev.anticrack.Main
   ```

2. **The service will automatically**:
   - Initialize all protection mechanisms
   - Start the game integration service on port 25565
   - Begin monitoring for threats
   - Wait for game connections

3. **Example Output**:
   ```
   === AntiCrack Protection System v1.0.0 ===
   Initializing advanced anti-reverse engineering protection...
   [AntiCrack] Starting protection systems...
   [AntiCrack] Starting debugger detection...
   [AntiCrack] Starting memory protection...
   [AntiCrack] Starting process integrity checks...
   [AntiCrack] Starting virtual machine detection...
   [AntiCrack] Starting EAC-style game integration service...
   [GameIntegration] Service started on port 25565
   [AntiCrack] All protection systems started successfully
   AntiCrack protection is now active and monitoring threats.
   ```

### Running Sample Game Client

1. **Start the sample game** (AntiCrack must be running first):
   ```bash
   java -cp build/classes/java/main dev.anticrack.examples.SampleGameClient
   ```

2. **The game will**:
   - Check if AntiCrack is running
   - Register and authenticate with AntiCrack
   - Start protected gameplay
   - Maintain heartbeat communication
   - Terminate if protection is lost

## 🎮 Game Integration Guide

### Integration Overview

Games must integrate with AntiCrack to run. The integration process follows these steps:

1. **Availability Check**: Verify AntiCrack service is running
2. **Registration**: Send game information and request registration
3. **Authentication**: Complete challenge-response authentication
4. **Communication**: Maintain heartbeat and status communication
5. **Monitoring**: Monitor AntiCrack availability and respond to threats

### Step-by-Step Integration

#### Step 1: Check AntiCrack Availability

```java
private boolean checkAntiCrackAvailability() {
    try (Socket testSocket = new Socket()) {
        testSocket.connect(new InetSocketAddress("localhost", 25565), 5000);
        System.out.println("AntiCrack service detected and available");
        return true;
    } catch (IOException e) {
        System.err.println("AntiCrack service not available - game cannot start!");
        return false;
    }
}
```

#### Step 2: Register with AntiCrack

```java
// Connect to AntiCrack service
Socket socket = new Socket("localhost", 25565);
BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

// Send registration request
String registrationRequest = "REGISTER:YourGameName:1.0.0:GAME_SIGNATURE";
writer.println(registrationRequest);

// Handle response
String response = reader.readLine();
if (response.startsWith("CHALLENGE:")) {
    String challengeData = response.substring(10);
    // Proceed to authentication
}
```

#### Step 3: Handle Authentication Challenge

```java
private boolean handleAuthenticationChallenge(String challengeData) {
    // For production, use proper AES encryption matching AntiCrack's CryptoProtection
    // For demo, use Base64 encoding of "ENCRYPTED:" + challengeData
    String challengeResponse = Base64.getEncoder()
        .encodeToString(("ENCRYPTED:" + challengeData).getBytes());
    
    writer.println(challengeResponse);
    
    String authResult = reader.readLine();
    if (authResult.startsWith("SUCCESS:")) {
        String authToken = authResult.substring(8);
        // Authentication successful - start game
        return true;
    }
    return false;
}
```

#### Step 4: Implement Heartbeat System

```java
// Send heartbeat every 4 seconds (faster than 15-second timeout)
ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);
executor.scheduleAtFixedRate(() -> {
    if (connected.get() && gameRunning.get()) {
        writer.println("HEARTBEAT:" + System.currentTimeMillis());
    }
}, 1000, 4000, TimeUnit.MILLISECONDS);
```

#### Step 5: Monitor AntiCrack Messages

```java
// Listen for messages from AntiCrack
executor.submit(() -> {
    try {
        String message;
        while (connected.get() && (message = reader.readLine()) != null) {
            if (message.equals("ACK")) {
                // Heartbeat acknowledged
            } else if (message.startsWith("TERMINATE:")) {
                String reason = message.substring(10);
                System.err.println("AntiCrack requested termination: " + reason);
                // Must terminate immediately for security
                System.exit(3);
            }
        }
    } catch (IOException e) {
        // Connection lost - must terminate
        System.err.println("Connection to AntiCrack lost - terminating for security");
        System.exit(2);
    }
});
```

#### Step 6: Report Game Status and Threats

```java
// Report game status periodically
writer.println("STATUS:Running normally - Level 5");

// Report detected threats
writer.println("THREAT:Suspicious memory access pattern detected");
```

## 🔧 API Reference

### Communication Protocol

AntiCrack uses a text-based protocol over TCP socket communication on port 25565.

#### Game → AntiCrack Messages

| Message Format | Description | Example |
|---|---|---|
| `REGISTER:name:version:signature` | Register game with AntiCrack | `REGISTER:MyGame:1.2.0:ABC123` |
| `HEARTBEAT:timestamp` | Send heartbeat to maintain connection | `HEARTBEAT:1634567890123` |
| `STATUS:description` | Report current game status | `STATUS:Running normally - Level 3` |
| `THREAT:description` | Report detected threat | `THREAT:Memory scanner detected` |

#### AntiCrack → Game Messages

| Message Format | Description | Action Required |
|---|---|---|
| `CHALLENGE:data` | Authentication challenge | Encrypt data and respond |
| `SUCCESS:token` | Authentication successful | Store token and continue |
| `ERROR:reason` | Request failed | Handle error and possibly terminate |
| `ACK` | Heartbeat acknowledged | Continue normal operation |
| `TERMINATE:reason` | Forced termination | Immediately exit application |

### Protection Levels

AntiCrack supports configurable protection levels:

- **LOW**: Basic threat detection with minimal performance impact
- **MEDIUM**: Standard protection with balanced security/performance
- **HIGH**: Comprehensive protection with active countermeasures
- **MAXIMUM**: All protection mechanisms enabled - highest security
- **CUSTOM**: User-defined protection configuration

### Threat Types

The system can detect and report various threat types:

- `DEBUGGER_DETECTED`: Debugging tools detected
- `MEMORY_PATCHING`: Memory modification attempts
- `PROCESS_INJECTION`: Process or DLL injection
- `VIRTUAL_MACHINE`: VM environment detected
- `API_HOOKING`: API interception detected
- `HARDWARE_BREAKPOINT`: Hardware debugging detected
- `TIMING_ANOMALY`: Suspicious timing patterns
- `CODE_INTEGRITY_VIOLATION`: Code tampering detected
- `UNKNOWN_THREAT`: Unclassified security threat

## 🏗️ Building from Source

### Prerequisites
- JDK 8+
- Gradle 6.0+

### Build Commands

```bash
# Clone the repository
git clone <repository-url>
cd AntiCrack

# Build the project
gradle build

# Run tests
gradle test

# Create distribution
gradle distZip
```

### Project Structure

```
AntiCrack/
├── src/main/java/dev/anticrack/
│   ├── AntiCrack.java              # Core protection system
│   ├── AntiCrackAPI.java           # Public API interface
│   ├── GameIntegrationService.java # EAC-style game integration
│   ├── CryptoProtection.java       # Cryptographic utilities
│   ├── ThreatType.java             # Threat enumeration
│   ├── ProtectionLevel.java        # Protection level configuration
│   ├── ThreatCallback.java         # Threat notification interface
│   ├── Main.java                   # Application entry point
│   └── examples/
│       └── SampleGameClient.java   # Example game integration
├── build.gradle                    # Build configuration
├── settings.gradle                 # Gradle settings
└── README.md                       # This file
```

## ⚙️ Configuration

### Protection Level Configuration

```java
AntiCrackAPI api = AntiCrackAPI.getInstance();
api.setProtectionLevel(ProtectionLevel.HIGH);
```

### Custom Threat Callbacks

```java
api.setThreatCallback(new ThreatCallback() {
    @Override
    public void onThreatDetected(ThreatType type, String description) {
        System.err.println("SECURITY ALERT: " + type + " - " + description);
        // Implement custom response (logging, network notification, etc.)
    }
    
    @Override
    public void onThreatMitigated(ThreatType type, String description) {
        System.out.println("Threat mitigated: " + description);
    }
});
```

## 🔒 Security Considerations

### For Game Developers

1. **Never bypass AntiCrack checks** - Always verify AntiCrack is running before starting your game
2. **Handle connection loss immediately** - Terminate your game if AntiCrack connection is lost
3. **Implement proper encryption** - Use the same cryptographic methods as AntiCrack for production
4. **Monitor continuously** - Maintain active communication with AntiCrack throughout gameplay
5. **Report threats** - Notify AntiCrack of any suspicious activity detected by your game

### Production Deployment

1. **Use strong encryption keys** - Replace demo encryption with production-grade keys
2. **Implement certificate validation** - Verify game signatures before allowing registration
3. **Configure appropriate protection levels** - Balance security needs with performance requirements
4. **Monitor logs actively** - Set up monitoring for threat detection events
5. **Update regularly** - Keep AntiCrack updated to protect against new attack vectors

## 🚨 Troubleshooting

### Common Issues

#### Game Can't Connect to AntiCrack
- Verify AntiCrack is running and listening on port 25565
- Check firewall settings allow connections to port 25565
- Ensure no other applications are using port 25565

#### Authentication Failures
- Verify encryption implementation matches AntiCrack's expectation
- Check that challenge responses are sent within the 30-second timeout
- Ensure proper Base64 encoding for demo implementations

#### Connection Timeouts
- Verify heartbeat is sent every 4 seconds or less
- Check network stability between game and AntiCrack
- Ensure game properly handles ACK responses

#### False Threat Detection
- Review protection level settings (consider lowering if too aggressive)
- Check for legitimate tools that might trigger detection
- Implement proper exception handling in threat callbacks

### Debug Mode

Enable verbose logging for troubleshooting:

```java
System.setProperty("anticrack.debug", "true");
```

## 📝 License

This project is provided as an example implementation of EAC-style anti-cheat protection. 

## 🤝 Contributing

Contributions are welcome! Please ensure all security improvements maintain backward compatibility with existing game integrations.

## 📞 Support

For technical support and integration assistance, please refer to the example implementations and API documentation provided in this README.

---

**⚠️ Security Notice**: This protection system is designed to be robust, but no anti-cheat system is 100% unbreakable. Continuous updates and monitoring are essential for maintaining security effectiveness.


# If you need to create your own anti-cheat or anti-crack, send a friend request to @thisistriwai on DISCORD
