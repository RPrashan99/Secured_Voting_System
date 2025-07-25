package main;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import votingSystemClientServer.voter;
import votingSystemRegistration.VoterRegistration;

public class VoterMain {

	public static void main(String[] args) 
			throws InvalidKeyException, UnknownHostException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		// TODO Auto-generated method stub
		
		System.out.println("\t---------- Voter Platform -----------");
		System.out.println("\t=====================================\n");
		
		Scanner scannerInput = new Scanner(System.in);
		
		String token = VoterRegistration.main(args, scannerInput);
		
		voter.main(args, token, scannerInput);
		
	}

}
