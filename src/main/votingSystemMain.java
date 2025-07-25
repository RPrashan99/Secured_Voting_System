package main;

import java.io.IOException;
import java.util.Scanner;

import votingSystemClientServer.votingSystem;
import votingSystemRegistration.VotingSystemRegistration;

public class votingSystemMain {

	public static void main(String[] args) 
			throws IOException, InterruptedException {
		// TODO Auto-generated method stub
		
		System.out.println("\t------- Voting system -------\n");
		
		Runnable voterRegistration = () -> {
			
			VotingSystemRegistration.main(args);
        	
        };
        
        Thread thread = new Thread(voterRegistration);
        thread.start();
        
        votingSystem.main(args);

	}

}
