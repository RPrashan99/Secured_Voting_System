package votingSystemClientServer;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class VoterHandler extends Thread{
	
	private Socket socket;
    private PrintWriter out;
    private PublicKey pkVsE;
    private PrivateKey skVsE;
    private PublicKey pkVsS;
    private PrivateKey skVsS;
    private String pKey;
    private String aesKey;
    
	//private final int AES_KEY_SIZE = 256;       // bits
    private final int GCM_IV_LENGTH = 12;       // bytes (recommended: 12)
    private final int GCM_TAG_LENGTH = 128; 
    
    private static final String TOKEN_DB_FILE = "tokens.db";
    private List<String> tokens = new ArrayList<>();
    //private String token = "RGB1234RGB";
    
    private String voterID;
    private String vote;

    public VoterHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        ) {
            out = new PrintWriter(socket.getOutputStream(), true);

            String message;
            while ((message = in.readLine()) != null) {
                //System.out.println("Received: " + message);
                
                String[] stringSplit = message.split(",");
                String mode = stringSplit[0];
                
                if(mode.equals("Connection_Request")) {
                	
                	System.out.println("\nConnection_Request recieved.");
                	
                	String reply = "Connection_Reply," + sendCertificateKeys();
                	
                	out.println(reply);
                	
                	System.out.println("Connection_Reply sent.");
                	
                }else if(mode.equals("Vote_Init")){
                	
                	System.out.println("\nVote_Init recieved.");
                	
                	System.out.println("Encrypted Message: " + message);
                	
                	String reply = createSignedBlindedVoteMessage(message);
                	
                	out.println(reply);
                	
                	System.out.println("Vote_Init_Reply sent.");
                	
                }else if(mode.equals("Vote_Submit")){
                	
                	System.out.println("\nVote_Submit recieved.");
                	
                	//System.out.println("Encrypted Message: " + message);
                	
                	boolean isSubmitVerified = verifyVoteSubmitMessage(message);
                	
                	if (isSubmitVerified) {
                		
                		String submitReply = createVoterID();
                		
                		out.println(submitReply);
                		
                		System.out.println("Vote_Submit_Reply sent.");
                		
                	} else {
                		
                		out.println("Submit_Verify_Failure");
                	}
                	
                }else {
                	System.out.println("Unknown command !");
                }
                
                
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            System.out.println("Error: " + e.getMessage());
            
        } finally {
            try {
                socket.close();
            } catch (IOException e) {}
        }
    }
    
    public String sendCertificateKeys() throws NoSuchAlgorithmException {
    	
    	KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		
		//For encryption
		KeyPair keyPairVsE = generator.generateKeyPair();
		pkVsE = keyPairVsE.getPublic();
		skVsE = keyPairVsE.getPrivate();
		
		//For sign
		KeyPair keyPairVsS = generator.generateKeyPair();
		pkVsS = keyPairVsS.getPublic();
		skVsS = keyPairVsS.getPrivate();
		
		String publicKeyEncrypt = Base64.getEncoder().encodeToString(pkVsE.getEncoded());
		String publicKeySign = Base64.getEncoder().encodeToString(pkVsS.getEncoded());
		
		String keys = publicKeyEncrypt + "," + publicKeySign;
    	
    	return keys;
    }
    
    public String enodeAndDecode(String text, String mode) {
    	
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

    public String createSignedBlindedVoteMessage(String message) 
    		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    	
    	String SignedBlindedVoteMessage = "";
    	
    	String decryptedVoteInitMessage = extractVoteInitMessage(message);
    	
    	JSONObject decryptedJSONInitMessage = new JSONObject(decryptedVoteInitMessage);
		
		//Extract token, BlindedVote and time stamp
		String extrctedToken = decryptedJSONInitMessage.getString("token");
		BigInteger extrctedBlindedVote = decryptedJSONInitMessage.getBigInteger("blindedVote");
		String extrctedTimeStamp = decryptedJSONInitMessage.getString("timeStamp");
		
		//Token verification
		boolean isTokenVerified = verifyToken(extrctedToken);
		
		//Time stamp verification (5min)
		boolean isTimeStampVerified = timeStampVerify(extrctedTimeStamp);
		
		if (isTokenVerified && isTimeStampVerified) {
			
			BigInteger d = ((java.security.interfaces.RSAPrivateKey) skVsS).getPrivateExponent();
			BigInteger Nv = ((java.security.interfaces.RSAPrivateKey) skVsS).getModulus();
			BigInteger signedBlindedVote = extrctedBlindedVote.modPow(d, Nv);
			
			String signedBlindedVoteString = signedBlindedVote.toString();
			
			String[] aesList = encryptAESText(signedBlindedVoteString, aesKey);
			
			SignedBlindedVoteMessage = "Vote_Init_Reply," + aesList[0] + "," + aesList[1];
			
			System.out.println("Signed Blinded message: " + SignedBlindedVoteMessage);
			
		} else {
			
			SignedBlindedVoteMessage = "Failure";
			
		}
		
		//System.out.println("signed Init Reply Message: " + SignedBlindedVoteMessage);
		
		return SignedBlindedVoteMessage;
    	
    }
    
    public String extractVoteInitMessage(String voteInit) 
    		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    	
    	String[] initMessageList = voteInit.split(",");
		//String splitMode = initMessageList[0];
		String splitedVoteInitMessage = initMessageList[1];
		String splitedAESKey = initMessageList[2];
		String splitedIV = initMessageList[3];
		
		//Decrypt AES key
		String decryptedAESKey = decryptRSAText(splitedAESKey, skVsE);
		aesKey = decryptedAESKey;
		System.out.println("Decrypted AES key: " + decryptedAESKey);
		
		//Decrypt vote Init Message
		String decryptedVoteInitMessage = decryptAESText(splitedVoteInitMessage, decryptedAESKey, splitedIV);
		//System.out.println("Decrypted VoteInitMessage: " + decryptedVoteInitMessage);
		
		System.out.println("Decrypted vote init object: " + decryptedVoteInitMessage);
		
		return decryptedVoteInitMessage;
    }
    
    public boolean verifyToken(String extrctedToken) {
    	
    	tokens = loadTokens();
    	
    	if(tokens.contains(extrctedToken)) {
    		removeToken(extrctedToken, tokens);
			return true;
		}else {
			//System.out.println("Token not verified");
			return false;
		}
    	
    }
    
    public List<String> loadTokens(){
    	try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(TOKEN_DB_FILE))) {
            List<String> allTokens = (List<String>) ois.readObject();
        	System.out.println("Tokens: " + allTokens);
            return allTokens;
        } catch (FileNotFoundException e) {
            System.out.println("No existing token database found. Starting fresh.");
            return new ArrayList<>(); // Return empty map if file doesn't exist
        } catch (Exception e) {
            System.out.println("Error loading voters: " + e.getMessage());
            return new ArrayList<>(); // Return empty map on error
        }
    }
    
    public void removeToken(String token, List<String> allTokens) {
    	
    	allTokens.remove(token);
    	saveTokesToFile(allTokens);
    }
    
    private static void saveTokesToFile(List<String> tokens) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(TOKEN_DB_FILE))) {
            oos.writeObject(tokens);
        } catch (Exception e) {
            System.out.println("Error saving voters: " + e.getMessage());
        }
    }
    
    public boolean verifyVoteSubmitMessage(String voteSubmitMessage) 
    		throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    	
    	String[] messageSplit = voteSubmitMessage.split(",");
    	
    	String IV = messageSplit[1];
    	String encryptedJson = messageSplit[2];

//    	int index = voteSubmitMessage.indexOf('{');
//    	String jsonPart = voteSubmitMessage.substring(index);
    	
    	String decryptedJson = decryptAESText(encryptedJson, aesKey, IV);
    	
    	System.out.println("Decrypted Vote Submit Message: " + decryptedJson);
    	
    	JSONObject extractedVoteSubmitMessage = new JSONObject(decryptedJson);
		
		String extractedVote = extractedVoteSubmitMessage.getString("vote");
		BigInteger extractedUnblindedVote = extractedVoteSubmitMessage.getBigInteger("unblindedVote");
		String extractedSubmitTime = extractedVoteSubmitMessage.getString("timeStamp");
		
		//verify time stamp
		if (timeStampVerify(extractedSubmitTime)) {
			//System.out.println("Submit time stamp verified");
		}else {
			//System.out.println("Submit time stamp not verified");
			return false;
		}
		
		BigInteger e = ((java.security.interfaces.RSAPublicKey) pkVsS).getPublicExponent();
		BigInteger N = ((java.security.interfaces.RSAPublicKey) pkVsS).getModulus();
		
		//signature verify by hashing extracted vote
		BigInteger signatureVS = extractedUnblindedVote.modPow(e, N);
		
		//hashing
		byte[] hashedExtractedVote = hashMessage(extractedVote);
		BigInteger hashedExtractedVoteInteger = new BigInteger(1, hashedExtractedVote);
	
		if(signatureVS.equals(hashedExtractedVoteInteger)) {
			vote = extractedVote;
			//System.out.println("Signature verified");
			return true;
		}else {
			//System.out.println("Signature not verified");
			return false;
		}
    }
    
    public String createVoterID() 
    		throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    	
    	SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[16];
        secureRandom.nextBytes(nonce);
		
		//vote ID create
		String voteID = "ID" + nonce.toString() + vote;
		
		String hashedVoteID = hashMessage(voteID).toString();
		
		voterID =  hashedVoteID;
		
		System.out.println("Voter ID created: " + voterID);
		
		String[] encryptedList = encryptAESText(voterID, aesKey);
		
		String submitReply = "Vote_Submit_Reply," + encryptedList[0] + "," + encryptedList[1];
		
		return submitReply;
    }
    
    public String getVoterID() {
    	
    	return voterID;
    }
    
    public String getVote() {
    	
    	return vote;
    }
    
  //Common function
    public byte[] hashMessage(String msg) 
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
		
		//System.out.println("Hashed Message: " + hashedMsg);
		
		return msgHashedBytes;
		
	}
	
	public String encryptRSAText(String msg, PublicKey pk) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		encryptCipher.init(Cipher.ENCRYPT_MODE, pk);
		byte[] byteMsg = msg.getBytes(StandardCharsets.UTF_8);
		byte[] encryptByteMsg = encryptCipher.doFinal(byteMsg);
		String encodedEncryptedMsg = Base64.getEncoder().encodeToString(encryptByteMsg);
		
		return encodedEncryptedMsg;
		
	}
	
	public String decryptRSAText(String encodedMsg, PrivateKey sk) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		decryptCipher.init(Cipher.DECRYPT_MODE, sk);
		byte[] decodedEncryptedMsg = Base64.getDecoder().decode(encodedMsg);
		byte[] decryptedBytes = decryptCipher.doFinal(decodedEncryptedMsg);
		String decryptedMsg = new String(decryptedBytes, StandardCharsets.UTF_8);
		
		return decryptedMsg;
		
	}
	
	public String[] encryptAESText(String text, String aesKey) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

        //Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        byte[] decodedKey = Base64.getDecoder().decode(aesKey);
        
        SecretKeySpec keySpec = new SecretKeySpec(decodedKey, "AES");

        //Encrypt
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        byte[] encryptedBytes = encryptCipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        // Base64 encode for transmission/storage
        String base64Encrypted = Base64.getEncoder().encodeToString(encryptedBytes);
        String base64Key = Base64.getEncoder().encodeToString(((SecretKey) keySpec).getEncoded());
        String base64IV = Base64.getEncoder().encodeToString(iv);
		
		String[] list = {base64Encrypted, base64IV, base64Key};
		
		return list;
	}
	
	public String decryptAESText(String base64Encrypted, String base64Key, String base64IV) 
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
	
	public String signText(String text, PrivateKey sk) 
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		
		byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
		
		Signature signature = Signature.getInstance("SHA256withRSA");
	        
        signature.initSign(sk);
        
        signature.update(textBytes);
        
        byte[] digitalSignature = signature.sign();
        
        String encodedSignature = Base64.getEncoder().encodeToString(digitalSignature);
        
        return encodedSignature;
	}
	
	public boolean verifySignature(String text, String originalData, PublicKey pk) 
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		
		byte[] signatureBytes = Base64.getDecoder().decode(text);
	    
	    Signature signature = Signature.getInstance("SHA256withRSA");
	    
	    signature.initVerify(pk);
	    
	    signature.update(originalData.getBytes());
	    
	    return signature.verify(signatureBytes);
	}
	
	public boolean timeStampVerify(String timeStamp) {
		
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
