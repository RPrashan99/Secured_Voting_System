package votingSystemClientServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

public class votingSystem {
	
	static int port = 7776;
	
	private static List<VoterHandler> voters = Collections.synchronizedList(new ArrayList<>());

	public static void main(String[] args) 
			throws IOException {
		
		System.out.println("Voting System submission Server initiated!");
		
		//create ServerSocket in a port
		ServerSocket serverSocket = new ServerSocket(port);
		
		//get both input and output from connection
		String input, output;
		
		Runnable voterTask = () -> {
        	
        	Scanner scannerInput = new Scanner(System.in);
        	
        	System.out.println("Voting in progress...");
        	
        	System.out.println("Voting close (yes): ");
        	String action = scannerInput.nextLine();
        	
        	if(action.equals("yes")) {
        		
        		voterFinalize();
        		
        	}
        };

        Thread thread = new Thread(voterTask);
        thread.start();
		
		try {
			
			while(!serverSocket.isClosed()) {
				try {
						
					Socket voterSocket = serverSocket.accept();
			        System.out.println("Voter connected: " + voterSocket);
			        
			        VoterHandler newVoter = new VoterHandler(voterSocket);
			        voters.add(newVoter);
			        newVoter.start();
					
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		} finally {
			serverSocket.close();
		}

	}
	
	public static void voterFinalize() {
		
		System.out.println("Voting closed. Final votings....");
		
		List<String> votingNames = new ArrayList<>();
		List<Integer> votingResults = new ArrayList<>();
		
		System.out.println("Voters: "+ voters);
		
		for (VoterHandler voter : voters) {
	        String id = voter.getVoterID();
	        String vote = voter.getVote();

	        if (vote == null) continue; // Skip if no vote submitted

	        System.out.println("Voter ID: " + id);
	        System.out.println("Vote: " + vote);

	        int index = votingNames.indexOf(vote);
	        if (index == -1) {
	            votingNames.add(vote);
	            votingResults.add(1);
	        } else {
	            int current = votingResults.get(index);
	            votingResults.set(index, current + 1);
	        }
	    }
		
		System.out.println("\n-------- Final results -------");
		
		System.out.printf("%-10s | %-6s%n", "Name", "Votes");
		System.out.println("-----------------------");

		for (int i = 0; i < votingNames.size(); i++) {
		    System.out.printf("%-10s | %-6d%n", votingNames.get(i), votingResults.get(i));
		}
		
	}

}
