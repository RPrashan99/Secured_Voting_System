package votingSystemRegistration;

import javax.crypto.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.io.*;
import java.util.concurrent.*;

public class VoterRegistration {
	
    private static KeyPair voterKeyPair;
    private static final SecureRandom random = new SecureRandom();
    private static final ExecutorService executor = Executors.newSingleThreadExecutor();
    
    private static String token;

    public static String main(String[] args, Scanner scannerInput) 
    		throws UnknownHostException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    	
    	// Generate voter's key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        voterKeyPair = keyGen.generateKeyPair();

        System.out.println("\t-------- Voter Registration ---------\n");

        try (Socket voterSocket = new Socket("localhost", 7777);
             BufferedReader in = new BufferedReader(new InputStreamReader(voterSocket.getInputStream()));
             PrintWriter out = new PrintWriter(voterSocket.getOutputStream(),true)) {

            // Set socket timeout
            voterSocket.setSoTimeout(10000);

            // 1. Receive server public key (Base64 encoded)
            String serverPublicKeyBase64 = in.readLine();
            PublicKey serverPublicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(
                            Base64.getDecoder().decode(serverPublicKeyBase64)));

            System.out.println("Connected to Voting System!");

            while (true) {
                System.out.println("\n=== Voting System Options ===");
                System.out.println("1. Register Voter");
                System.out.println("2. Exit");
                System.out.print("Choose an option: ");

                try {
                    int choice = getValidChoice(scannerInput);

                    switch (choice) {
                        case 1:
                            registerVoter(scannerInput, out, in, serverPublicKey);
                            break;
                        case 2:
                            out.println("EXIT");
                            System.out.println("Disconnecting from server...");
                            executor.shutdownNow();
                            return token;
                        default:
                            System.out.println("Invalid option. Please try again.");
                    }
                } catch (InputMismatchException e) {
                    System.out.println("Invalid input. Please enter a number between 1-4.");
                    scannerInput.nextLine(); // Clear the invalid input
                    return "error";
                }
            }
        }
    	
//        try (Scanner scannerInput = new Scanner(System.in)) {
//            
//        } catch (ConnectException e) {
//            System.err.println("Could not connect to server: " + e.getMessage());
//        } catch (Exception e) {
//            System.err.println("Client error: " + e.getMessage());
//        } finally {
//            executor.shutdown();
//        }
    }

    private static int getValidChoice(Scanner scanner) throws InputMismatchException {
        while (true) {
            try {
                System.out.print("Choose an option (1-2): ");
                int choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline

                if (choice >= 1 && choice <= 4) {
                    return choice;
                } else {
                    System.out.println("Please enter a number between 1 and 2.");
                }
            } catch (InputMismatchException e) {
                scanner.nextLine(); // Clear the invalid input
                throw e;
            }
        }
    }

    private static void startMessageListener(BufferedReader in) {
        executor.execute(() -> {
            try {
                while (!executor.isShutdown()) {
                    String message = in.readLine();
                    if (message == null) {
                        System.out.println("\nServer disconnected unexpectedly");
                        System.exit(0);
                    }
                    System.out.println("\n[Server Notification] " + message);
                }
            } catch (IOException e) {
                if (!executor.isShutdown()) {
                    System.err.println("Error reading from server: " + e.getMessage());
                }
            }
        });
    }

    private static void registerVoter(Scanner scanner, PrintWriter out, BufferedReader in, PublicKey serverPublicKey) {
        try {
            System.out.println("\n=== Voter Registration ===");

            // Get and validate inputs
            System.out.print("Enter full name: ");
            String name = scanner.nextLine().trim();
            if (name.isEmpty()) {
                System.out.println("Name cannot be empty");
                return;
            }

            System.out.print("Enter ID number (EG/YYYY/XXXX): ");
            String id = scanner.nextLine().trim();
            if (!id.matches("EG/\\d{4}/\\d{4}")) {
                System.out.println("Invalid ID format");
                return;
            }

            // Generate random value
            int randomValue = random.nextInt();

            // Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey sessionKey = keyGen.generateKey();

            // Encrypt session key with RSA
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedKey = rsaCipher.doFinal(sessionKey.getEncoded());		

            // Prepare data
            String publicKeyBase64 = Base64.getEncoder().encodeToString(
                    voterKeyPair.getPublic().getEncoded());
            String dataToSend = String.join("|",
                    name, id, String.valueOf(randomValue), publicKeyBase64);

            // Encrypt data with AES
            Cipher encryptyAesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            encryptyAesCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
            byte[] encryptedData = encryptyAesCipher.doFinal(dataToSend.getBytes(StandardCharsets.UTF_8));

            System.out.println("Encrypted data (AES): " + encryptedData.toString());
            System.out.println("Encrypted AES key (RSA): " + encryptedKey.toString());
            // Send data
            out.println(Base64.getEncoder().encodeToString(encryptedKey));
            out.println(Base64.getEncoder().encodeToString(encryptedData));

            // Get and process response
            String response = in.readLine();
            if (response == null) {
                System.out.println("No response from server");
                return;
            }
            
            System.out.println("System response: " + response);
            
            Cipher decryptAesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            decryptAesCipher.init(Cipher.DECRYPT_MODE, sessionKey);
            
            byte[] decryptedResponse = decryptAesCipher.doFinal(Base64.getDecoder().decode(response));
            String[] parts = new String(decryptedResponse, StandardCharsets.UTF_8).split("\\|");

            System.out.println("Decrypted System response: " + parts[0] + "," + parts[1] + "," + parts[2]);
            
            if (parts[0].equals("SUCCESS")) {
                System.out.println("\nRegistration Successful!");
                System.out.println("Voter Token: " + parts[1]);
                System.out.println("Random Value Verification: " +
                        (Integer.parseInt(parts[2]) == randomValue + 1 ? "Valid" : "Invalid"));
                
                token = parts[1];
                
            } else {
                System.out.println("\nRegistration failed: " + parts[0]);
            }
        } catch (Exception e) {
            System.err.println("Registration error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
}
