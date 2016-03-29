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


import java.util.*;
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
	//private static final int maxClientsCount = 10;
	//private static final clientThread[] threads = new clientThread[maxClientsCount];


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
		clientThread client = null;
		while(true){
			try{
				clientSocket = serverSocket.accept();
				client = new clientThread(clientSocket);
				//int i = 0;
				/*for(i = 0; i<maxClientsCount; i++){
					if(threads[i] == null){
						new clientThread(clientSocket);
						break;
					}
				}*/
				/*if(i == maxClientsCount){
					PrintStream os = new PrintStream(clientSocket.getOutputStream());
					os.println("Server too busy. Try later.");
					os.close();
					clientSocket.close();
				}*/
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
class clientThread {

	private String clientName = null;
	private DataInputStream is = null;
	private DataOutputStream os = null;
	private Socket clientSocket = null;
	//private final clientThread[] threads;
	//private int maxClientsCount;
	private InetAddress address;//address that holds the IP


	public clientThread(Socket clientSocket){
		this.clientSocket = clientSocket;
		this.address = this.clientSocket.getInetAddress();//get the address from the connecting client
		//this.threads = threads;
		//.maxClientsCount = threads.length;
		startThis();
	}


	public void startThis(){
		//int maxClientsCount = this.maxClientsCount;
		//clientThread[] threads = this.threads;
		try{
			/*
			* Create input and output streams for this client.
			*/
			is = new DataInputStream(clientSocket.getInputStream());
			os = new DataOutputStream(clientSocket.getOutputStream());
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
			String temp = "Connection with Server established";
			os.write(temp.getBytes("UTF-8"));
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

			/*synchronized(this){
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
			}*/

			int msgLength = is.readInt();
			System.out.println("Length: " + msgLength);
			byte[] message = null;
			if (msgLength >0){
				message = new byte[msgLength];
				is.readFully(message, 0, message.length);
			}
			System.out.println("THIS IS THE RECEIVED MESSAGE......................................");
			for (int i = 0; i < msgLength; i++){
				System.out.print(message[i]+",");
			}


			//line var holds the messages received from the client
			try{
				//do crypto stuff here
				System.out.println("starting...");

				Security.addProvider(new BouncyCastleProvider());

				//GET CLEINT PUBLIC KEY KUC
				Path path = Paths.get("client_public_key.txt");
				byte [] CKey = Files.readAllBytes(path);
				PublicKey KUC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(CKey));

				System.out.println("public key gotten...");

				//errything is in line
				/*byte[] message = line1.getBytes("UTF-8");
				System.out.println(message);*/
				//split up
				byte[] keyPart = new byte[128];
				byte[] crypPart = new byte[message.length-128];
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
				SecretKeySpec sk = new SecretKeySpec(secretKey.getEncoded(), "AES");
				System.out.println("shared key constructed...");

				Path path2 = Paths.get("client_iv.txt");
				byte[] iv = Files.readAllBytes(path2);

				System.out.println("IV VECTOR");
				for (int i = 0; i < iv.length; i++){
					System.out.print(iv[i]+",");
				}

				System.out.println("secret key length: " + secretKey.getEncoded().length);
				System.out.println("secret key spec length: " + sk.getEncoded().length);
				for (int i = 0; i < secretKey.getEncoded().length;i++){
					System.out.print(secretKey.getEncoded()[i]+",");
				}
				System.out.println("");

				System.out.println("ENCRYPTED PACKAGE");
				for (int i = 0; i < crypPart.length; i++){
					System.out.print(crypPart[i]+",");
				}
				System.out.println("");

				byte[] encryptedPackage = null;
				Cipher aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				aescipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
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




				if (Arrays.equals(decryptedHash,digest)){
					System.out.println("fuck yea");
				}


			}

			catch (Exception e){
				System.err.println(e);
			}






			/*synchronized(this){
				for(int i = 0; i < maxClientsCount; i++){
					if(threads[i] != null && threads[i] != this && threads[i].clientName != null){
						threads[i].os.println( "* * * The user " + name + " is leaving the chat room!!! * * *");
					}
				}
			}*/
			//os.write("Connection with Server ended");

			//os.println( "* * * Bye " + name + " * * * ");
			/*
			* Clean up . Set the current thread variable to null so that a new client
			* could be accepted by the server .
			*/
			/*synchronized(this){
				for(int i = 0; i < maxClientsCount; i++){
					if(threads[i] == this){
						threads[i] = null;
					}
				}
			}*/

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
