package votingSystemRegistration;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class VotingSystemRegistration {
    private static final int PORT = 7777;
    private static Map<String, Voter> voters = new ConcurrentHashMap<>();
    private static KeyPair votingSystemKeyPair;
    private static final String VOTER_DB_FILE = "voters.db";
    private static final String TOKEN_DB_FILE = "tokens.db";
    private static final ExecutorService threadPool = Executors.newCachedThreadPool();
    private static ServerSocket serverSocket;
    private static List<String> tokens = new ArrayList<>();
    //

    public static void main(String[] args) {
        try {
        	System.out.println("Voting System Registration initiated!");
            // Initialize the voting system keys
            initializeSystemKeys();
            // Load existing voters from file
            loadVoters();
            startServer();
        } catch (Exception e) {
            System.err.println("Server error: " + e.getMessage());
        } finally {
            shutdownServer();
        }
    }

    private static void initializeSystemKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        votingSystemKeyPair = keyGen.generateKeyPair();
    }

    private static void startServer() throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("Server started on port " + PORT);
        // Send server public key in Base64 format
        System.out.println("System Public Key: " +
                Base64.getEncoder().encodeToString(votingSystemKeyPair.getPublic().getEncoded()));

        while (!serverSocket.isClosed()) {
            try {
                Socket voterSocket = serverSocket.accept();
                threadPool.execute(new VoterHandler(voterSocket));
                System.out.println("\nNew voter connected: " + voterSocket.getInetAddress() + "\n");
            } catch (SocketException e) {
                if (!serverSocket.isClosed()) {
                    System.err.println("Server socket error: " + e.getMessage());
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static synchronized void loadVoters() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(VOTER_DB_FILE))) {
            Map<String, Voter> voters = (Map<String, Voter>) ois.readObject();
            voters.putAll(voters);
            //System.out.println("Loaded " + voters.size() + " voters from database.");
        } catch (FileNotFoundException e) {
            System.out.println("No existing voter database found. Starting fresh.");
        } catch (Exception e) {
            System.out.println("Error loading voters: " + e.getMessage());
        }
    }

    private static void saveVoters() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(VOTER_DB_FILE))) {
            oos.writeObject(voters);
            System.out.println("\t\t Voter is saved");
        } catch (Exception e) {
            System.out.println("Error saving voters: " + e.getMessage());
        }
    }

    private static void shutdownServer() {
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
            	
                serverSocket.close();
            }
            threadPool.shutdown();
            if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
            saveVoters();
            System.out.println("Server shutdown complete.");
        } catch (Exception e) {
            System.err.println("Error during shutdown: " + e.getMessage());
        }
    }

    private static class VoterHandler implements Runnable {
        private Socket voterSocket;

        public VoterHandler(Socket socket) {
            this.voterSocket = socket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(
                    new InputStreamReader(voterSocket.getInputStream()));
                 PrintWriter out = new PrintWriter(
                         new OutputStreamWriter(voterSocket.getOutputStream()), true)) {

                // 1. Send server public key
                out.println(Base64.getEncoder().encodeToString(
                        votingSystemKeyPair.getPublic().getEncoded()));

                // 2. Receive encrypted session key
                String encryptedKeyBase64 = null;
                
                while((encryptedKeyBase64 = in.readLine()) == null) {
                	
                }
                
                //System.out.println("Checkpoint_1");

                // 3. Decrypt session key
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaCipher.init(Cipher.DECRYPT_MODE, votingSystemKeyPair.getPrivate());
                byte[] sessionKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedKeyBase64));
                SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

                //System.out.println("Checkpoint_2");
                
                // 4. Receive encrypted data
                String encryptedDataBase64 = in.readLine();
                if (encryptedDataBase64 == null) return;
                
                //System.out.println("Checkpoint_3");

                // 5. Decrypt data
                Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                aesCipher.init(Cipher.DECRYPT_MODE, sessionKey);
                byte[] encryptedData = Base64.getDecoder().decode(encryptedDataBase64);
                String decryptedData = new String(aesCipher.doFinal(encryptedData), StandardCharsets.UTF_8);

                String[] parts = decryptedData.split("\\|");
                if (parts.length != 4) {
                    sendErrorResponse(out, aesCipher, "Invalid data format");
                    return;
                }
                
                //System.out.println("Checkpoint_4");

                // Process registration
                String name = parts[0];
                String id = parts[1];
                int randomValue = Integer.parseInt(parts[2]);
                PublicKey voterPublicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(parts[3])));

                String response;
                if (!id.matches("EG/\\d{4}/\\d{4}")) {
                    response = "ERROR: Invalid ID format";
                } else if (voters.containsKey(id)) {
                    response = "ERROR: Voter ID already exists";
                } else {
                    String token = UUID.randomUUID().toString();
                    voters.put(id, new Voter(name, id, token, new KeyPair(voterPublicKey, null)));
                    saveVoters();
                    addToken(token);
                    loadTokens();
                    response = "SUCCESS|" + token + "|" + (randomValue + 1);
                }
                
                //System.out.println("Checkpoint_5");

                // Encrypt and send response
                byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
                
                //System.out.println("reponse size: " + responseBytes.length);
                
                Cipher decryprAesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                decryprAesCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
                byte[] encryptedResponse = decryprAesCipher.doFinal(responseBytes);
                out.println(Base64.getEncoder().encodeToString(encryptedResponse));
                
                //System.out.println("Checkpoint_6");

            } catch (Exception e) {
                System.out.println("Error handling client: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    voterSocket.close();
                } catch (IOException e) {
                    System.out.println("Error closing socket: " + e.getMessage());
                }
            }
        }

        private void sendErrorResponse(PrintWriter out, Cipher cipher, String message) {
            try {
                String error = "ERROR|" + message;
                byte[] encrypted = cipher.doFinal(error.getBytes(StandardCharsets.UTF_8));
                out.println(Base64.getEncoder().encodeToString(encrypted));
            } catch (Exception e) {
                System.out.println("Failed to send error response: " + e.getMessage());
            }
        }
    }
    
    static class Voter implements Serializable {
        private final String name;
        private final String id;
        private final String token;
        private transient KeyPair keyPair;

        // Store public key bytes since KeyPair isn't Serializable
        private final byte[] publicKeyBytes;

        public Voter(String name, String id, String token, KeyPair keyPair) {
            this.name = name;
            this.id = id;
            this.token = token;
            this.keyPair = keyPair;
            this.publicKeyBytes = keyPair.getPublic().getEncoded();
        }

        public String getName() { return name; }
        public String getId() { return id; }
        public String getToken() { return token; }

        public KeyPair getKeyPair() {
            if (keyPair == null && publicKeyBytes != null) {
                try {
                    PublicKey publicKey = KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                    keyPair = new KeyPair(publicKey, null); // Private key not stored for security
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            return keyPair;
        }

        private void writeObject(ObjectOutputStream oos) throws IOException {
            oos.defaultWriteObject();
        }

        private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
            ois.defaultReadObject();
        }
    }
    
    private static void addToken(String token) {
    	
        tokens.add(token);
        saveTokesToFile(tokens);
    	
    }
    
    private static void saveTokesToFile(List<String> tokens) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(TOKEN_DB_FILE))) {
            oos.writeObject(tokens);
        } catch (Exception e) {
            System.out.println("Error saving voters: " + e.getMessage());
        }
    }

    private static void loadTokens() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(TOKEN_DB_FILE))) {
            List<String> tokens = (List<String>) ois.readObject();
            System.out.println("Tokens: " + tokens);
        } catch (FileNotFoundException e) {
            System.out.println("No existing voter database found. Starting fresh.");
            //return new HashMap<>(); // Return empty map if file doesn't exist
        } catch (Exception e) {
            System.out.println("Error loading voters: " + e.getMessage());
            //return new HashMap<>(); // Return empty map on error
        }
    }
}
