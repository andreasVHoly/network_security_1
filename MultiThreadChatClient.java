import java.io.DataInputStream;
import java.io.PrintStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.*;


//newly added
import java.io.*;
import javax.xml.bind.DatatypeConverter;
import java.nio.file.*;

import java.util.zip.*;//for zipping
import javax.crypto.*;//for crypto
import java.security.*;//for crypto
import java.security.spec.*;
import javax.crypto.spec.*;


//import org.apache.commons.codec.digest.*;//for hashing
//new bouncy castle libs
import org.bouncycastle.openpgp.PGPPrivateKey;//pgp crypto
import org.bouncycastle.jce.provider.BouncyCastleProvider;




public class MultiThreadChatClient{
	//The client socket
	private static Socket clientSocket = null;
	// The output stream
	private static DataOutputStream os = null;
	// The input stream
	private static DataInputStream is = null ;
	private static BufferedReader inputLine = null;
	private static boolean closed = false; //Volatile variable?


	public static void main (String[] args){

		// The default port.
		int portNumber = 2222;
		// The default host.
		String host = "localhost";


		/*
		* Open a socket on a given host and port. Open input and output streams .
		*/
		try{
			clientSocket = new Socket(host,portNumber);
			inputLine = new BufferedReader(new InputStreamReader(System.in));
			//use these below to allow passing byte arrays
			os = new DataOutputStream(clientSocket.getOutputStream());
			is = new DataInputStream(clientSocket.getInputStream());
		}
		catch(UnknownHostException e){
			System.err.println("Don't know about host " +host);
		}
		catch(IOException e){
			System.err.println("Couldn't get I/O for the connection to the host "+ host);
		}



		//adding bouncy castle provider
		Security.addProvider(new BouncyCastleProvider());
		//default message
		String message = "This is what we want to encrypt!!!!!!!! This is a message we are testing";


		//get input from the user to get a message to decrypt
		Scanner in = new Scanner(System.in);
		System.out.println("Please enter a message to encrypt: ");
		if(!host.equals("")){
			message = in.nextLine();
		}


		try{

			//CREATE A HASH OF THE MESSAGE
			System.out.println("_.:SETTING UP AUTHENTICATION:._");
			byte[] digest = null;
			byte[] signedMessage = null;

			System.out.println("\t.:CREATING MESSAGE DIGEST:.");
			System.out.println("\t\tOriginal Message: " + message);
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(message.getBytes("UTF-8"));
			digest = md.digest();
			int mdValue = 0;
			for (int i = 0; i < digest.length; i++){
				mdValue += digest[i];
			}

			System.out.println("\t\tMessage Digest Summation: " + mdValue);

			System.out.println("\t\tMessage Digest Size: " + digest.length);

			//create private and public keys for client
			System.out.println("\t.:CREATING PRIVATE AND PUBLIC KEY PAIR:.");
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keys = keyGen.generateKeyPair();

			//get the key from the generator
			PrivateKey KRC = keys.getPrivate();
			PublicKey KUC = keys.getPublic();

			//convert to bytes
			byte[] KUCArray = KUC.getEncoded();

			//for printing
			int count1 = 0;
			for (int i = 0; i < KUCArray.length; i++){
				count1 += KUCArray[i];
			}
			System.out.println("\t\tPublic Key Summation: " + count1);

			System.out.println("\t\tWriting Public Key to file \"client_public_key.txt\"");
			//write out the public key to a file
			FileOutputStream fos = new FileOutputStream("client_public_key.txt");
			fos.write(KUCArray);
			fos.close();


			System.out.println("\t.:SIGNING HASH WITH CLIENTS PRIVATE KEY:.");

			System.out.println("\t\tEncrypting Hash with Private Key");
			//sign hash with private key
			byte[] encryptedHash = null;
			Cipher RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			RSAcipher.init(Cipher.ENCRYPT_MODE, KRC);
			encryptedHash = RSAcipher.doFinal(digest);

			int count2 = 0;
			for (int i = 0; i < encryptedHash.length; i++){
				count2 += encryptedHash[i];
			}

			System.out.println("\t\tEncrypted Hash Summation: " + count2);

			//concantenate hash and original message
			System.out.println("\t.:CONCATENATING SIGNATURE AND MESSAGE:.");
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			//add signature
			outputStream.write(encryptedHash);
			//add message
			outputStream.write(message.getBytes("UTF-8"));
			//concat
			signedMessage = outputStream.toByteArray();
			outputStream.close();

			int count3 = 0;
			for (int i = 0; i < signedMessage.length; i++){
				count3 += signedMessage[i];
			}
			System.out.println("\t\tAthenticated Packet Summation: " + count3);

			System.out.println("\t.:COMPRESSING AUTHENTICATED PACKET:.");
			//zip the above

			//using chunks of 1024 bytes
			byte[] output = new byte[1024];
			//create defalter
			Deflater compress = new Deflater();
			compress.setInput(signedMessage);
			//use byte array to avoid running out of space
			ByteArrayOutputStream o = new ByteArrayOutputStream(signedMessage.length);
			compress.finish();

			//create zip
			while(!compress.finished()){
				int count = compress.deflate(output);
				o.write(output,0,count);
			}
			o.close();
			compress.end();

			//zipped message
			byte[] op = o.toByteArray();

			int count4 = 0;
			for (int i = 0; i < op.length; i++){
				count4 += op[i];
			}
			System.out.println("\t\tCompressed Packet Summation: " + count4);

			System.out.println("_.:AUTHENTICATION COMPLETE:._");
			System.out.println("_.:SETTING UP CONFIDENTIALITY:._");




			//encrypt the zip with shared key

			//create shared key
			System.out.println("\t.:CREATING SHARED KEY:.");
			KeyGenerator secretKeyGen = KeyGenerator.getInstance("AES");
	        secretKeyGen.init(128);
			//GET KEY
	        SecretKey secretKey = secretKeyGen.generateKey();
			//new key spec
			SecretKeySpec k = new SecretKeySpec(secretKey.getEncoded(), "AES");

			int count5 = 0;
			for (int i = 0; i < secretKey.getEncoded().length; i++){
				count5 += secretKey.getEncoded()[i];
			}
			System.out.println("\t\tShared Key Summation: " + count5);


			System.out.println("\t.:ENCRYPTING COMPRESSED PACKET WITH SHARED KEY:.");
			//create cipher for encryption and encrypt zip\

			byte[] encryptedPackage = null;
			Cipher aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aescipher.init(Cipher.ENCRYPT_MODE, k);
			encryptedPackage = aescipher.doFinal(op);


			int count5 = 0;
			for (int i = 0; i < encryptedPackage.length; i++){
				count5 += encryptedPackage[i];
			}
			System.out.println("\t\tEncrypted Compressed Packet Summation: " + count5);

			System.out.println("\t\tExtracting the IV for decryption");

			//get iv from cipher
			byte[] iv = aescipher.getIV();

			int count6 = 0;
			for (int i = 0; i < iv.length; i++){
				count6 += iv[i];
			}
			System.out.println("\t\tIV summation: " + count6);
			//write iv to a file
			System.out.println("\t\tWriting IV to file \"client_iv.txt\"");
			FileOutputStream fos2 = new FileOutputStream("client_iv.txt");
			fos2.write(iv);
			fos2.close();


			System.out.println("\t.:ENCRYPTING SHARED KEY WITH SEVERS PUBLIC KEY:.");
			// get server key

			Path path = Paths.get("server_public_key.txt");
			byte [] SKey = Files.readAllBytes(path);

			PublicKey KUS = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(SKey));


			//encrypt shared key with public key of server
			byte[] encryptedKey = null;
			Cipher packet = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			packet.init(Cipher.ENCRYPT_MODE, KUS); //TODO we need the public key of server here
			encryptedKey = packet.doFinal(secretKey.getEncoded());

			//concat the encrypyted shared key and the encrypted zip

			ByteArrayOutputStream finalMessage = new ByteArrayOutputStream( );
			finalMessage.write(encryptedKey);
			finalMessage.write(encryptedPackage);
			System.out.println("Key size " + encryptedKey.length);
			byte[] fin = finalMessage.toByteArray();
			finalMessage.close();


			//send off
			//fin is final packet
			String msg = new String(fin);
			//System.out.println(lol);

			//String msg = "line one\nline two\nl3\nl4";
			/*for (int k = 0; k < msg.length; k++ ) {
				if ()
			}*/
			//System.out.println("test");
			int index = 0;
			String edit = "";
			//System.out.println("WTF");
			//System.out.println("***old " + msg);

			/*while( (index = msg.indexOf("\n")) != -1){
				edit += msg.substring(0,index);
				edit += "nl_c";
				edit += msg.substring(index+1,msg.length());
				msg = edit;
			}*/
			//msg = "_start_" + msg + "_end_";

			/*System.out.println("***new " + "_start_" + msg + "_end_");
			os.println("_start_" + msg + "_end_");*/

			System.out.println("THIS IS THE SENT MESSAGE......................................");
			System.out.println("Length: " + fin.length);
			for (int i = 0; i < fin.length; i++){
				System.out.print(fin[i]+",");
			}
			os.writeInt(fin.length);
			os.write(fin);


		}
		catch (Exception e){
			System.err.println(e);
		}
		//end

		/*
		* If every thing has been initialized then we want to write some data to the
		* socket we have opened a connection to on the port portNumber .
		*/
		/*if(clientSocket != null && os != null && is != null){
			System.out.println("fucking method kak is called");
			try{
				/* Create a thread to read from the server.
				new Thread (new MultiThreadChatClient()).start();
				while(!closed){
					System.out.println(":::::"+inputLine.readLine().trim());
					os.println(inputLine.readLine().trim());
				}
				/*
				* Close the output stream , close the input stream, close the socket .

				os.close();
				is.close();
				clientSocket.close();
			}
			catch(IOException e){
				System.err.println("IOException : " + e);
			}
		}*/
	}

}
