package votingSystem;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
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

public class VoterAndSystem {
	
    private static final int AES_KEY_SIZE = 256;       // bits
    private static final int GCM_IV_LENGTH = 12;       // bytes (recommended: 12)
    private static final int GCM_TAG_LENGTH = 128; 

	public static void main(String[] args) 
			throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
		
		System.out.println("----- Voter and voting system -----");
		
		//For Voting system
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		
		//For encryption
		KeyPair keyPairVsE = generator.generateKeyPair();
		PublicKey pkVsE = keyPairVsE.getPublic();
		PrivateKey skVsE = keyPairVsE.getPrivate();
		
		//For sign
		KeyPair keyPairVsS = generator.generateKeyPair();
		PublicKey pkVsS = keyPairVsS.getPublic();
		PrivateKey skVsS = keyPairVsS.getPrivate();
		
		//For voter
		KeyPair keyPairV = generator.generateKeyPair();
		PublicKey pkV = keyPairV.getPublic();
		PrivateKey skV = keyPairV.getPrivate();
		
		KeyGenerator generatorAES = KeyGenerator.getInstance("AES");
		generatorAES.init(AES_KEY_SIZE);
        SecretKey aesKey = generatorAES.generateKey();

		
		//Steps to process
		
		Scanner scannerInput = new Scanner(System.in);
		
		//1. Send voting init message
		System.out.println("--- Vote time ---");
		System.out.println("1. Alice");
		System.out.println("2. Bob");
		System.out.println("3. Timmy");
		
		System.out.println("Select a choice (name): ");
		String vote = scannerInput.nextLine();
		
		System.out.println("Input verified");
		
		//hashing vote 
		byte[] hashedVote = hashMessage(vote);
		BigInteger hashedVoteInteger = new BigInteger(1, hashedVote);
		
		//message blinding
		BigInteger randomFactor = new BigInteger(1024, new Random());
		
		BigInteger e = ((java.security.interfaces.RSAPublicKey) pkVsS).getPublicExponent();
		BigInteger N = ((java.security.interfaces.RSAPublicKey) pkVsS).getModulus();
		
		BigInteger blindedMessage = hashedVoteInteger.multiply(randomFactor.modPow(e, N).mod(N));
		
		//Get time stamp and token
		LocalTime currentTime = LocalTime.now();
		String stringCurrentTime = currentTime.toString();
		String token = "RGB1234RGB";
		
		//format message
		JSONObject messageObject = new JSONObject();
		messageObject.put("token", token);
		messageObject.put("blindedVote", blindedMessage);
		messageObject.put("timeStamp", stringCurrentTime);
		
		String voteInitMessage = messageObject.toString();
		
		//Encrypt voteInitMessage using AES
		String[] listAES = encryptAESText(voteInitMessage, aesKey);
		
		//Encrypt AES key using RSA
		String encryptedAESKey = encryptRSAText(listAES[2], pkVsE);
		
		//Total vote init message
		String totalVoteInitMessage = "Vote_Init," + listAES[0] + "," + encryptedAESKey + "," + listAES[1];
		
		System.out.println("Encrypted AES Key: " + encryptedAESKey);
		System.out.println("Encrypted VoteInitMessage: " + listAES[0]);
		System.out.println("Encrypted Total VoteInitMessage: " + totalVoteInitMessage);
		
		////////////////////////////////////////////////////////////////////
		
		//2. Voting system init reply
		
		//Extract mode, key and message
		String[] initMessageList = totalVoteInitMessage.split(",");
		String splitMode = initMessageList[0];
		String splitedVoteInitMessage = initMessageList[1];
		String splitedAESKey = initMessageList[2];
		String splitedIV = initMessageList[3];
		
		//Decrypt AES key
		String decryptedAESKey = decryptRSAText(splitedAESKey, skVsE);
		
		//Decrypt vote Init Message
		String decryptedVoteInitMessage = decryptAESText(splitedVoteInitMessage, decryptedAESKey, splitedIV);
		System.out.println("Decrypted VoteInitMessage: " + decryptedVoteInitMessage);
		
		//Convert to JSON object
		JSONObject decryptedJSONInitMessage = new JSONObject(decryptedVoteInitMessage);
		
		//Extract token, BlindedVote and time stamp
		String extrctedToken = decryptedJSONInitMessage.getString("token");
		BigInteger extrctedBlindedVote = decryptedJSONInitMessage.getBigInteger("blindedVote");
		String extrctedTimeStamp = decryptedJSONInitMessage.getString("timeStamp");
		
		//Verify token
		System.out.println("Extracted Token: " + extrctedToken);
		
		if(token.equals(extrctedToken) && timeStampVerify(extrctedTimeStamp)) {
			System.out.println("Token and TimeStamp verified");
		}else {
			System.out.println("Token and TimeStamp not verified");
		}
		
		//String extrctedBlindedVoteString = extrctedBlindedVote.toString();
		
		//sign the extracted blind vote
		//String signedBlindedVote = signText(extrctedBlindedVoteString, skVsS);
		BigInteger d = ((java.security.interfaces.RSAPrivateKey) skVsS).getPrivateExponent();
		BigInteger Nv = ((java.security.interfaces.RSAPrivateKey) skVsS).getModulus();
		BigInteger signedBlindedVote = extrctedBlindedVote.modPow(d, Nv);
		
		String signedInitReplyMessage = "Signed," + signedBlindedVote;
		
		System.out.println("signed Init Reply Message: " + signedInitReplyMessage);
		
		//3. Unblind the vote send to VS
		
		//Extract mode and signed Blinded Vote
		String[] listSigned = signedInitReplyMessage.split(",");
		
		//mode check and extract signed Blinded Vote
		String extractedSignedBlindedVote = listSigned[1];

		//unblind the signed vote
		BigInteger signedBlindedVoteInteger = new BigInteger(extractedSignedBlindedVote);
		BigInteger unBlindedVoteInteger = signedBlindedVoteInteger.multiply(randomFactor.modInverse(N)).mod(N);
		
		System.out.println("unBlinded Vote: " + unBlindedVoteInteger);
		
		//time stamp create
		LocalTime currentTimeUnblind = LocalTime.now();
		String currentTimeUnblindString = currentTimeUnblind.toString();
		
		//Vote submit format
		JSONObject voteMessage = new JSONObject();
		voteMessage.put("vote", vote);
		voteMessage.put("unblindedVote", unBlindedVoteInteger);
		voteMessage.put("timeStamp", currentTimeUnblindString);
		
		String voteSubmitMessage = voteMessage.toString();
		System.out.println("Vote Submit Message: " + voteSubmitMessage);
		
		//4. verify the unblinded vote
		//Extract vote, unblindedVote, timeStamp
		
		JSONObject extractedVoteSubmitMessage = new JSONObject(voteSubmitMessage);
		
		String extractedVote = extractedVoteSubmitMessage.getString("vote");
		BigInteger extractedUnblindedVote = extractedVoteSubmitMessage.getBigInteger("unblindedVote");
		String extractedSubmitTime = extractedVoteSubmitMessage.getString("timeStamp");
		
		//verify time stamp
		if (timeStampVerify(extractedSubmitTime)) {
			System.out.println("Submit time stamp verified");
		}else {
			System.out.println("Submit time stamp not verified");
		}
		
		//signature verify by hashing extracted vote
		BigInteger signatureVS = extractedUnblindedVote.modPow(e, N);
		
		//hashing
		byte[] hashedExtractedVote = hashMessage(extractedVote);
		BigInteger hashedExtractedVoteInteger = new BigInteger(1, hashedExtractedVote);
	
		if(signatureVS.equals(hashedExtractedVoteInteger)) {
			System.out.println("Signature verified");
		}else {
			System.out.println("Signature not verified");
		}
		
		//5. Submit the vote
		
		//random number generate
		SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[16];
        secureRandom.nextBytes(nonce);
		
		//vote ID create
		String voteID = "ID" + nonce.toString() + extractedVote;
		
		String hashedVoteID = hashMessage(voteID).toString();
		
		//send voteID to voter
		
		System.out.println("------Output-------");
		System.out.println("VoteID: " + hashedVoteID);
		System.out.println("Vote: " + extractedVote);
	}
	
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
