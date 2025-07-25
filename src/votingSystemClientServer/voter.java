package votingSystemClientServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.LocalTime;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class voter {
	
	private static final int AES_KEY_SIZE = 256;       // bits
    private static final int GCM_IV_LENGTH = 12;       // bytes (recommended: 12)
    private static final int GCM_TAG_LENGTH = 128; 
	
	static int port = 7776;
	
	private static PublicKey pkVsE;
	private static PublicKey pkVsS;
	
	private static PrivateKey skV;
	private static PublicKey pkV;
	
	private static SecretKey aesKey;
	
	private static BigInteger randomFactor;
	
	private static String vote;
	private static String voterID;

	public static void main(String[] args, String token, Scanner scannerInput) 
			throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		System.out.println("\n\t -------- Voter Selection --------");
		System.out.println("\t =================================\n");
		
		//get local IP address
		//InetAddress ipAddress = InetAddress.getLocalHost();
		
		//Socket socket = new Socket(ipAddress, port);
		
		Socket socket = new Socket("localhost", port);
		
		System.out.println("System: Avaiable....\n");
		
		//write data to server
		PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
		
		//read data from server
		BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		String mode = "Entry", message = "";
		
		try {
			
			//send data
			while(true) {
				
				String input = "", output = "";
				
				if (mode.equals("Connection_Reply")){
					
					System.out.println("Connection_Reply Recieved.");
					
					String[] messageSplit = message.split(",");
					String publicKeyEncrypt = messageSplit[1];
					String publicKeySign = messageSplit[2];
					
					pkVsE = generatePublicKeyFromString(publicKeyEncrypt);
					pkVsS = generatePublicKeyFromString(publicKeySign);
					
					//Initialize voting and generate key
					String vote = votingInitilize(scannerInput);
					generateAESKeys();
					
					// Create INIT message
					System.out.println("Vote: " + token);
					output = getInitMessage(vote, token);
					
					System.out.println("\nVote_Init Sent.");
					
				} else if (mode.equals("Vote_Init_Reply")) {
					
					System.out.println("\nVote_Init_Reply Recieved.");
					
					output = createVoteSubmitMessage(message);
					
					System.out.println("\nVote_Submit sent.");
					
				} else if (mode.equals("Vote_Submit_Reply")) {
					
					System.out.println("\nVote_Submit_Reply Recieved.");
					
					recieveVoterID(message);
					
					System.out.println("\nVote_Submit Success !");
					System.out.println("Voter ID: " + voterID);
					
				}else if (mode.equals("Entry")) {
					
					output = "Connection_Request";
					System.out.println("Connection request sent.");
					
				} else if(mode.equals("Submit_Verify_Failure")) {
					
					System.out.println("Submit_Verify_Failure !");
					break;
					
				} else {
					System.out.println("Unknown command !");
					break;
				}
				
				mode = "";
				
				if(output != "") {
					out.println(output);
				}
				
				if ((input = in.readLine()) != null) {
					System.out.println("System Message: " + input);
					String[] stringSplit = input.split(",");
					mode = stringSplit[0];
					System.out.println("Mode: " + mode);
					message = input;
				}
				
			}
		
		} finally {
			socket.close();
			out.close();
			in.close();
		}

	}
	
	public static String enodeAndDecode(String text, String mode) {
    	
    	String output = "";
    	
    	if(mode.equals("encode")) {
    		
    		byte[] textByte = text.getBytes();
    		output = Base64.getEncoder().encode(textByte).toString();
    		
    	}else {
    		
    		byte[] textByte = text.getBytes();
    		output = Base64.getDecoder().decode(textByte).toString();
    		
    	}
    	
    	return output;
    }
	
	public static PublicKey generatePublicKeyFromString(String keyStr) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] keyBytes = Base64.getDecoder().decode(keyStr);
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    return keyFactory.generatePublic(spec);
	    
	}
	
	public static String votingInitilize(Scanner scannerInput) {
		
		//1. Send voting init message
		System.out.println("\n\t--- Vote Select ---");
		System.out.println("\t1. Alice");
		System.out.println("\t2. Bob");
		System.out.println("\t3. Timmy");
		
		System.out.println("Select a choice (name): ");
		
		if (scannerInput.hasNextLine()) {
		    vote = scannerInput.nextLine();
		} else {
		    System.out.println("No more input available");
			vote = "Alice";
		}
		
		System.out.println("Choice: " + vote);
		
		//vote = scannerInput.nextLine();
		
		return vote;
		
	}
	
	public static void generateAESKeys() throws NoSuchAlgorithmException {
		
		KeyGenerator generatorAES = KeyGenerator.getInstance("AES");
		generatorAES.init(AES_KEY_SIZE);
        aesKey = generatorAES.generateKey();
		
	}
	
	public static String getInitMessage(String vote, String token) 
			throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		//hashing vote 
				byte[] hashedVote = hashMessage(vote);
				BigInteger hashedVoteInteger = new BigInteger(1, hashedVote);
				
				//message blinding
				randomFactor = new BigInteger(1024, new Random());
				
				BigInteger e = ((java.security.interfaces.RSAPublicKey) pkVsS).getPublicExponent();
				BigInteger N = ((java.security.interfaces.RSAPublicKey) pkVsS).getModulus();
				
				BigInteger blindedMessage = hashedVoteInteger.multiply(randomFactor.modPow(e, N).mod(N));
				
				System.out.println("Blinded Message: " + blindedMessage);
				
				//Get time stamp and token
				LocalTime currentTime = LocalTime.now();
				String stringCurrentTime = currentTime.toString();
				//String token = "RGB1234RGB";
				
				//format message
				JSONObject messageObject = new JSONObject();
				messageObject.put("token", token);
				messageObject.put("blindedVote", blindedMessage);
				messageObject.put("timeStamp", stringCurrentTime);
				
				String voteInitMessage = messageObject.toString();
				
				System.out.println("Vote message object: " + voteInitMessage);
				
				//Encrypt voteInitMessage using AES
				String[] listAES = encryptAESText(voteInitMessage, aesKey);
				
				//Encrypt AES key using RSA
				String encryptedAESKey = encryptRSAText(listAES[2], pkVsE);
				
				//Total vote init message
				String totalVoteInitMessage = "Vote_Init," + listAES[0] + "," + encryptedAESKey + "," + listAES[1];
				
				System.out.println("Encrypted Vote Init message: " + totalVoteInitMessage);
				
				return totalVoteInitMessage;
				
	}
	
	public static String createVoteSubmitMessage(String message) 
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		BigInteger unBlindedVoteInteger = unblindSignedVote(message);
		
		LocalTime currentTimeUnblind = LocalTime.now();
		String currentTimeUnblindString = currentTimeUnblind.toString();
		
		//Vote submit format
		JSONObject voteMessage = new JSONObject();
		voteMessage.put("vote", vote);
		voteMessage.put("unblindedVote", unBlindedVoteInteger);
		voteMessage.put("timeStamp", currentTimeUnblindString);
		
		String voteMessageString = voteMessage.toString();
		System.out.println("Original Vote Submit Message: " + voteMessageString);
		
		String[] listAES = encryptAESText(voteMessageString, aesKey);
		
		System.out.println("Encrypted Vote Submit Message: " + listAES[0]);
		
		String voteSubmitMessage = "Vote_Submit," + listAES[1] + "," + listAES[0];
		
		return voteSubmitMessage;
	}
	
	public static BigInteger unblindSignedVote(String signedInitReplyMessage) {
		
		BigInteger N = ((java.security.interfaces.RSAPublicKey) pkVsS).getModulus();
		
		String[] listSigned = signedInitReplyMessage.split(",");
		
		//mode check and extract signed Blinded Vote
		String extractedSignedBlindedVote = listSigned[1];

		//unblind the signed vote
		BigInteger signedBlindedVoteInteger = new BigInteger(extractedSignedBlindedVote);
		BigInteger unBlindedVoteInteger = signedBlindedVoteInteger.multiply(randomFactor.modInverse(N)).mod(N);
		
		System.out.println("unBlinded Vote: " + unBlindedVoteInteger);
		
		return unBlindedVoteInteger;
	}
	
	public static void recieveVoterID(String message) {
		
		String[] stringSplit = message.split(",");
		
		voterID = stringSplit[1];
		
	}
	
	//Common function
	public static byte[] hashMessage(String msg) 
			throws NoSuchAlgorithmException {
		
		byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
		
		MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
		
		//Hashing
		byte[] msgHashedBytes = msgDigest.digest(msgBytes);
		
		//create the hash string
		StringBuilder sBuilder = new StringBuilder();
		for (byte b : msgHashedBytes) {
			String msgByte = String.format("%02x", b);
			sBuilder.append(msgByte);
		}
		
		String hashedMsg = sBuilder.toString();
		
		System.out.println("Hashed Message: " + hashedMsg);
		
		return msgHashedBytes;
		
	}
	
	public static String encryptRSAText(String msg, PublicKey pk) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		encryptCipher.init(Cipher.ENCRYPT_MODE, pk);
		byte[] byteMsg = msg.getBytes(StandardCharsets.UTF_8);
		byte[] encryptByteMsg = encryptCipher.doFinal(byteMsg);
		String encodedEncryptedMsg = Base64.getEncoder().encodeToString(encryptByteMsg);
		
		return encodedEncryptedMsg;
		
	}
	
	public static String decryptRSAText(String encodedMsg, PrivateKey sk) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		decryptCipher.init(Cipher.DECRYPT_MODE, sk);
		byte[] decodedEncryptedMsg = Base64.getDecoder().decode(encodedMsg);
		byte[] decryptedBytes = decryptCipher.doFinal(decodedEncryptedMsg);
		String decryptedMsg = new String(decryptedBytes, StandardCharsets.UTF_8);
		
		return decryptedMsg;
		
	}
	
	public static String[] encryptAESText(String text, SecretKey aesKey) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

        //Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        //Encrypt
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        byte[] encryptedBytes = encryptCipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        // Base64 encode for transmission/storage
        String base64Encrypted = Base64.getEncoder().encodeToString(encryptedBytes);
        String base64Key = Base64.getEncoder().encodeToString(aesKey.getEncoded());
        String base64IV = Base64.getEncoder().encodeToString(iv);
		
		String[] list = {base64Encrypted, base64IV, base64Key};
		
		return list;
	}
	
	public static String decryptAESText(String base64Encrypted, String base64Key, String base64IV) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		byte[] decodedEncrypted = Base64.getDecoder().decode(base64Encrypted);
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        byte[] decodedIV = Base64.getDecoder().decode(base64IV);

        SecretKeySpec keySpec = new SecretKeySpec(decodedKey, "AES");
        GCMParameterSpec gcmSpec2 = new GCMParameterSpec(GCM_TAG_LENGTH, decodedIV);

        Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec2);

        byte[] decryptedBytes = decryptCipher.doFinal(decodedEncrypted);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        
        return decryptedMessage;
	}
	
	public static String signText(String text, PrivateKey sk) 
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		
		byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
		
		Signature signature = Signature.getInstance("SHA256withRSA");
	        
        signature.initSign(sk);
        
        signature.update(textBytes);
        
        byte[] digitalSignature = signature.sign();
        
        String encodedSignature = Base64.getEncoder().encodeToString(digitalSignature);
        
        return encodedSignature;
	}
	
	public static boolean verifySignature(String text, String originalData, PublicKey pk) 
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		
		byte[] signatureBytes = Base64.getDecoder().decode(text);
	    
	    Signature signature = Signature.getInstance("SHA256withRSA");
	    
	    signature.initVerify(pk);
	    
	    signature.update(originalData.getBytes());
	    
	    return signature.verify(signatureBytes);
	}
	
	public static boolean timeStampVerify(String timeStamp) {
		
		boolean isVerified = false;
		
		LocalTime currentTime = LocalTime.now();
		LocalTime time = LocalTime.parse(timeStamp);
		
		Duration duration = Duration.between(currentTime, time);
		long seconds = duration.getSeconds();
		
		if (seconds < 300) {
			isVerified = true;
		}
		
		return isVerified;
	}


}
