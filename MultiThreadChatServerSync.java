import java.io.DataInputStream;
import java.io.PrintStream;
import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetAddress;
import java.io.*;





import javax.xml.bind.DatatypeConverter;

import java.util.zip.*;//for zipping
import javax.crypto.*;//for crypto
import java.security.*;//for crypto
import java.security.spec.*;
import java.io.*;
import javax.xml.bind.DatatypeConverter;
import java.nio.file.*;
import javax.crypto.spec.*;
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
			System.out.println("IO_ExceptionERROR" + e);
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
				System.out.println("IOException Error" + e);
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

			PrivateKey KRS = null;
			//create server keys
			try{
				KeyPairGenerator keyGen2 = KeyPairGenerator.getInstance("RSA");
				keyGen2.initialize(1024);
				KeyPair serverkeys = keyGen2.generateKeyPair();

				KRS = serverkeys.getPrivate();
				PublicKey KUS = serverkeys.getPublic();
				//Write KUS to textfile server_public_key.txt
				byte[] KUSArray = KUS.getEncoded();

				FileOutputStream fos = new FileOutputStream("server_public_key.txt");
				fos.write(KUSArray);
				fos.close();
			}
			catch (Exception e){
				System.out.println("Exception" + e);
			}

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
				System.out.println("Here comes the message from client:");
				System.out.println("msg received " + line);
				//we need to end connection


				int index = 0;
				String edit = "";
				while( (index = line.indexOf("nl_c")) != -1){
					edit += line.substring(0,index);
					edit += "\n";
					edit += line.substring(index+4,line.length());
					line = edit;
				}

				System.out.println("msg altered " + line);


				//System.out.println(line);
				if(line.startsWith( "/quit")){
					break;
				}


				//line var holds the messages received from the client
				/*try{
					//do crypto stuff here
					System.out.println("starting...");

					Security.addProvider(new BouncyCastleProvider());

					//GET CLEINT PUBLIC KEY KUC
					Path path = Paths.get("client_public_key.txt");
					byte [] CKey = Files.readAllBytes(path);
					PublicKey KUC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(CKey));

					System.out.println("public key gotten...");

					//errything is in line
					byte[] message = line.getBytes();
					System.out.println(message);
					//split up
					byte[] keyPart = new byte[128];
					byte[] crypPart = new byte[message.length];
					for(int i = 0; i < 128; i++){
						keyPart[i] = message[i];
					}
					System.out.println("message split intmediate...");
					for(int j = 128, k = 0; j < message.length; j++, k++){
						crypPart[k] = message[j];
					}

					System.out.println("message split...");

					//CONFIDENTIALITY

					//decrypt with the public key of client
					byte[] encryptedKey = null;
					Cipher packet = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					packet.init(Cipher.DECRYPT_MODE, KRS);
					encryptedKey = packet.doFinal(keyPart);

					System.out.println("shared key decrypted...");
					//decrypt shared key

					SecretKey secretKey = new SecretKeySpec(encryptedKey, 0, encryptedKey.length, "AES");

					System.out.println("shared key constructed...");
					byte[] encryptedPackage = null;
					Cipher aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
					aescipher.init(Cipher.DECRYPT_MODE, secretKey);
					encryptedPackage = aescipher.doFinal(crypPart);


					System.out.println("decrypted with shared key...");

					//AUTHENTICAION


					//


					Inflater decompresser = new Inflater();
					decompresser.setInput(encryptedPackage, 0, encryptedPackage.length);
					byte[] result = new byte[1024];


					ByteArrayOutputStream o2 = new ByteArrayOutputStream(encryptedPackage.length);
					while(!decompresser.finished()){
						int count = decompresser.inflate(result);
						o2.write(result,0,count);
					}
					o2.close();
					byte[] op2 = o2.toByteArray();
					decompresser.end();
					System.out.println("unzipped...");

					//op2 is decompressed message
					byte[] sigPart = new byte[128];
					byte[] messagePart = new byte[op2.length-128];
					for(int i = 0; i < 128; i++){
						sigPart[i] = op2[i];
					}

					for(int j = 128, k = 0; j < op2.length; j++, k++){
						messagePart[k] = op2[j];
					}

					System.out.println("split message again...");

					String origMessage = new String(messagePart);
					System.out.println("message reads: " + origMessage );
					//create hash of the message

					byte[] digest = null;
					MessageDigest md = MessageDigest.getInstance("SHA-256");
					md.update(messagePart);
					digest = md.digest();

					System.out.println("own hash created...");


					//sign hash with private key
					byte[] decryptedHash = null;
					Cipher hashCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					hashCipher.init(Cipher.DECRYPT_MODE, KUC);
					decryptedHash = hashCipher.doFinal(sigPart);




					if (decryptedHash == digest){
						System.out.println("fuck yea");
					}


				}

				catch (Exception e){
					System.err.println(e);
				}*/

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
