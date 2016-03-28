import java.io.DataInputStream;
import java.io.PrintStream;
import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetAddress;





import javax.xml.bind.DatatypeConverter;

import java.util.zip.*;//for zipping
import javax.crypto.*;//for crypto
import java.security.*;//for crypto
//import org.apache.commons.codec.digest.*;//for hashing
//new bouncy castle libs
import org.bouncycastle.openpgp.PGPPrivateKey;//pgp crypto
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/*
* A chat server that delivers public and private messages .
*/
public class MultiThreadChatServerSync{
	// The server socket .
	private static ServerSocket serverSocket = null;

	// The client socket .
	private static Socket clientSocket = null;

	// This chatserver can accept up to maxClientsCount clients ’ connections .
	private static final int maxClientsCount = 10;
	private static final clientThread[] threads = new clientThread[maxClientsCount];


	public static void main(String args[]){
		// The default port number.
		int portNumber = 2222;
		if(args.length < 1){
			System.out.println("Usage : java MultiThreadChatServerSync <portNumber>\n" + "Now using port number= " + portNumber);
		}
		else{
			portNumber = Integer.valueOf(args[0]).intValue();
		}
		 /*
		 * Open a server socket on the portNumber (default 2222). Note that we can
		 * not choose a port less than 1023 if weare not privileged users (root).
		 */
		try{
			serverSocket = new ServerSocket(portNumber);
		}
		catch(IOException e){
			System.out.println(e);
		}

		 /*
		* Create a client socket for each connection and pass it to a new client
		* thread .
		*/
		while(true){
			try{
				clientSocket = serverSocket.accept();
				int i = 0;
				for(i = 0; i<maxClientsCount; i++){
					if(threads[i] == null){
						(threads[i] = new clientThread(clientSocket, threads)).start();
						break;
					}
				}
				if(i == maxClientsCount){
					PrintStream os = new PrintStream(clientSocket.getOutputStream());
					os.println("Server too busy. Try later.");
					os.close();
					clientSocket.close();
				}
			}
			catch(IOException e){
				System.out.println(e);
			}
		}
	}//main
}//class


/*
* The chat client thread . This client thread opens the input and the output
* streams for a particular client , ask the client's name , informs all the
* clients connected to the server about the fact that a new client has joined
* the chat room , and as long as it receive data , echos that data back to all
* other clients. The thread broadcast the incoming messages to all clients and
* routes the private message to the particular client . When a client leaves the
* chat room this thread informs all the clients about that and terminates.
*/
class clientThread extends Thread{

	private String clientName = null;
	private DataInputStream is = null;
	private PrintStream os = null;
	private Socket clientSocket = null;
	private final clientThread[] threads;
	private int maxClientsCount;
	private InetAddress address;//address that holds the IP


	public clientThread(Socket clientSocket, clientThread[] threads){
		this.clientSocket = clientSocket;
		this.address = this.clientSocket.getInetAddress();//get the address from the connecting client
		this.threads = threads;
		maxClientsCount = threads.length;
	}


	public void run(){
		int maxClientsCount = this.maxClientsCount;
		clientThread[] threads = this.threads;
		try{
			/*
			* Create input and output streams for this client.
			*/
			is = new DataInputStream(clientSocket.getInputStream());
			os = new PrintStream(clientSocket.getOutputStream());
			String name = "user";


			//name is automatically assigned now
			/*while(true){
				os.println("Enter your name.");
				name = is.readLine().trim();
				if(name.indexOf('@') == -1){
					break;
				}
				else{
					os.println("The name should not contain '@' character.");
				}
			}*/

			/* Welcome the new the client. */
			//os.println("Welcome " + name + " to our chat room.\nTo leave enter /quit in a new line.");
			os.println("Connection with Server established");
			System.out.println(name + " started a connection...");
			synchronized(this){
				for(int i = 0; i < maxClientsCount; i++){
					if(threads[i] != null &&  threads[i] == this){
						clientName = "@" + name;
						break;
					}
				}
				for(int i = 0 ; i < maxClientsCount ; i++){
					if(threads[i] != null && threads[i] != this){
						threads[i].os.println("* * * A new user " + name + " with address " + address + " entered the chat room!!! * * *");
					}
				}
			}

			/* Start the conversation . */
			while(true){
				//message received
				String line = is.readLine();
				//we need to end connection
				if(line.startsWith( "/quit")){
					break;
				}


				//line var holds the messages received from the client
				try{
					//do crypto stuff here
					Security.addProvider(new BouncyCastleProvider());

					//private and public keys for the server -> need public key in client -> maybe we should make a sharing class somehow? ensure keys are always the same?
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
					keyGen.initialize(1024);
					KeyPair keys = keyGen.generateKeyPair();

					PrivateKey KRS = keys.getPrivate();
					PublicKey KUS = keys.getPublic();

					//CONFIDENTIALITY




					//AUTHENTICAION


					//create hash of the message


					//uncommented as incomplete
				/*	byte[] digest = null;
					byte[] signedMessage = null;
					try{
						MessageDigest md = MessageDigest.getInstance("SHA-256");
						md.update(message.getBytes("UTF-8"));//adding message in - needs to be the ouput from previous coode  TODO
						digest = md.digest();



						//sign hash with private key
						byte[] encryptedHash = null;
						Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
						cipher.init(Cipher.DECRYPT_MODE, KRC);//need KUC here!!!! TODO
						encryptedHash = cipher.doFinal(digest);//this needs to be signed hash from previous step TODO

						if (encryptedHash == digest){//TODO? is this right
							System.out.println("Success");
						}*/

				}

				catch (Exception e){
					System.err.println(e);
				}

				//dont really need below as we dont want to echo messages
				/* If the message is private sent it to the given client. */
			/*	if(line.startsWith("@")){
					String[]words = line.split("\\s", 2);
					if(words.length > 1 && words[1] != null){
						words[1] = words[1].trim();
						if(!words[1].isEmpty()){
							synchronized(this){
								for(int i = 0; i < maxClientsCount; i++){
									if(threads[i] != null && threads[i] != this && threads[i].clientName != null && threads[i].clientName.equals(words[0])){
											threads[i].os.println("< " + name + "> " + words[1]);

											//Echo this message to let the client know the private message was sent .

											//TODO
											this.os.println("> "+ name + "> " + words[1]);
											break;
									}
								}
							}
						}
					}
				}

				//we will work in public domain, won't use the private chat function
				else{
					//The message is public , broadcast it to all other clients .
					//TODO
					synchronized(this){
						for(int i = 0; i < maxClientsCount; i++){
							if(threads[i] != null && threads[i].clientName != null){
								//this is where we ouput --> line is the data we sent from client
								threads[i].os.println("< " + name + "> " + line);
							}
						}
					}
				}*/
			}

			synchronized(this){
				for(int i = 0; i < maxClientsCount; i++){
					if(threads[i] != null && threads[i] != this && threads[i].clientName != null){
						threads[i].os.println( "* * * The user " + name + " is leaving the chat room!!! * * *");
					}
				}
			}
			os.println("Connection with Server ended");
			//os.println( "* * * Bye " + name + " * * * ");
			/*
			* Clean up . Set the current thread variable to null so that a new client
			* could be accepted by the server .
			*/
			synchronized(this){
				for(int i = 0; i < maxClientsCount; i++){
					if(threads[i] == this){
						threads[i] = null;
					}
				}
			}

			/*
			* close the output stream , close the input stream , close the socket .
			*/
			is.close();
			os.close();
			clientSocket.close();
		}
		catch(IOException e){
		}
	}
}//class
