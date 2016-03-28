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
//import org.apache.commons.codec.digest.*;//for hashing
//new bouncy castle libs
import org.bouncycastle.openpgp.PGPPrivateKey;//pgp crypto
import org.bouncycastle.jce.provider.BouncyCastleProvider;




public class MultiThreadChatClient implements Runnable{
	//The client socket
	private static Socket clientSocket = null;
	// The output stream
	private static PrintStream os = null;
	// The input stream
	private static DataInputStream is = null ;
	private static BufferedReader inputLine = null;
	private static boolean closed = false; //Volatile variable?


	public static void main (String[] args){

		// The default port.
		int portNumber = 2222;
		// The default host.
		String host = "localhost";

		//took below out to make straight connection
		//Scanner in = new Scanner(System.in);
		//System.out.println("Please enter your desired IP address: ");

		/*if(!host.equals("")){
			host = in.nextLine();
		}
		if(args.length < 2){
			System.out.println("Usage: java MultiThreadChatClient <host> <portNumber>\n"+ "Now using host= " + host + ", portNumber= "+ portNumber);
		}
		else{
			host = args[0];
			portNumber = Integer.valueOf(args[1]).intValue();
		}*/


		/*
		* Open a socket on a given host and port. Open input and output streams .
		*/
		try{
			clientSocket = new Socket(host,portNumber);
			inputLine = new BufferedReader(new InputStreamReader(System.in));
			os = new PrintStream(clientSocket.getOutputStream());
			is = new DataInputStream(clientSocket.getInputStream());
		}
		catch(UnknownHostException e){
			System.err.println("Don't know about host " +host);
		}
		catch(IOException e){
			System.err.println("Couldn't get I/O for the connection to the host "+ host);
		}



		//do crypto stuff here
		Security.addProvider(new BouncyCastleProvider());
		//message we are sending
		//String message = "Lol";
		String message = "This is what we want to encrypt!!!!!!!! Lol. we are now testing the zipping and want to ceajd hfvjh  dskhba dhsd jhsad ada dj adj adj da d ldkkf nhd fj df bfddf ankfdbj f ";

		//create hash of the message
		byte[] digest = null;
		byte[] signedMessage = null;
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(message.getBytes("UTF-8"));
			digest = md.digest();

			System.out.println("Digest Size: " + digest.length);

			//create private and public keys for client

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keys = keyGen.generateKeyPair();

			PrivateKey KRC = keys.getPrivate();
			PublicKey KUC = keys.getPublic();
			byte[] KUCArray = KUC.getEncoded();

			FileOutputStream fos = new FileOutputStream("client_public_key.txt");
			fos.write(KUCArray);
			fos.close();

			// //Write client public key to file for Server
			// BufferedWriter fileWriter = new BufferedWriter(new FileWriter("client_public_key.txt"));
			//
			// for (int i = 0; i < KUCArray.length; i++) {
			// 	fileWriter.write(KUCArray[i]);
			// }
			// fileWriter.close();

			//sign hash with private key
			byte[] encryptedHash = null;
			Cipher RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			RSAcipher.init(Cipher.ENCRYPT_MODE, KRC);
			encryptedHash = RSAcipher.doFinal(digest);


			//String privateKey = new String(Base64.encodeBase64(KRC.getEncoded(), 0,KRC.getEncoded().length, Base64.NO_WRAP));
			//String publicKey = new String(Base64.encode(KUC.getEncoded(), 0,KUC.getEncoded().length, Base64.NO_WRAP));
			System.out.println("Signed Hash Size: " + encryptedHash.length);
			System.out.println("Client Private Key Algorithm " + KRC.getAlgorithm());
			System.out.println("Client Private Key " + KRC);
			System.out.println("Client Public Key Algorithm " + KUC.getAlgorithm());
			System.out.println("Client Public Key " + KUC);


			//concantenate hash and original message
			//signedMessage = encryptedHash + message.getBytes();


			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write(encryptedHash);
			outputStream.write(message.getBytes());

			signedMessage = outputStream.toByteArray();
			outputStream.close();
			System.out.println("Signed Message Size: " + signedMessage.length);

			//zip the above TODO

			byte[] output = new byte[1024];

			Deflater compress = new Deflater();
			compress.setInput(signedMessage);
			ByteArrayOutputStream o = new ByteArrayOutputStream(signedMessage.length);
			compress.finish();

			//this could break because we might have more data
			int zipLen = 0;
			int initSize = 100;
			while(!compress.finished()){
				int count = compress.deflate(output);
				o.write(output,0,count);
			}
			o.close();
			/*if((zipLen = compress.deflate(output)) == 0){
				System.out.println("FOK");
			}*/
			compress.end();

			byte[] op = o.toByteArray();

			System.out.println("legth of zip " + op.length);

			System.out.println("\noriginal......................");

			for (int i = 0;	i < signedMessage.length ; i++) {
				System.out.print(signedMessage[i]+",");
			}
			System.out.println("\nzipped data......................");
			for (int j = 0;	j < op.length ; j++) {
				System.out.print(op[j]+",");
			}
			System.out.println("\n");
			//TODO put this on server side

			/*Inflater decompresser = new Inflater();
			decompresser.setInput(op, 0, op.length);
			byte[] result = new byte[1024];


			ByteArrayOutputStream o2 = new ByteArrayOutputStream(signedMessage.length);
			while(!decompresser.finished()){
				int count = decompresser.inflate(result);
				o2.write(result,0,count);
			}
			o2.close();
			byte[] op2 = o2.toByteArray();
			//int resultLength = decompresser.inflate(result);
			decompresser.end();



			System.out.println("\nDecompressed Message......................");


			for (int j = 0;	j < op2.length ; j++) {
				System.out.print(op2[j]+",");
			}

			System.out.println("\n");*/



			//encrypt the zip with shared key TODO

			//create shared key
			//PGPSecretKey

			KeyGenerator secretKeyGen = KeyGenerator.getInstance("AES");
	        secretKeyGen.init(128);
	        SecretKey secretKey = secretKeyGen.generateKey();

			//create cipher for encryption and encrypt zip\

			byte[] encryptedPackage = null;
			Cipher aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aescipher.init(Cipher.ENCRYPT_MODE, secretKey);
			encryptedPackage = aescipher.doFinal(op);


			//TODO get server key
			// BufferedReader fileReader = new BufferedReader(new FileReader("server_public_key.txt"));
			// String s = fileReader.readLine();  //read in the byte array from textfile
			// fileReader.close();
			// String[] byteRep = s.split("");
			// for (int i = 0; i < byteRep.length; i++) {
			// 	System.out.println(Byte.parseByte(byteRep[i]));
			// }
			// //Parse string into byte array
			// byte[] bytes = new byte[10];//Byte.parseByte(s);
			// System.out.println(s);
			// System.out.println(bytes);
			// FileInputStream fis = new FileInputStream("client_public_key.txt");
			Path path = Paths.get("server_public_key.txt");
			byte [] SKey = Files.readAllBytes(path);

			PublicKey KUS = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(SKey));


			//encrypt shared key with public key of server TODO
			byte[] encryptedKey = null;
			Cipher packet = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			packet.init(Cipher.ENCRYPT_MODE, KUS); //TODO we need the public key of server here
			encryptedKey = packet.doFinal(secretKey.getEncoded());

			//concat the encrypyted shared key and the encrypted zip TODO

			ByteArrayOutputStream finalMessage = new ByteArrayOutputStream( );
			finalMessage.write(encryptedKey);
			finalMessage.write(encryptedPackage);
			System.out.println("Key size " + encryptedKey.length);
			byte[] fin = finalMessage.toByteArray();
			finalMessage.close();


			//send off TODO
			//fin is final packet
			String lol = new String(fin);
			//System.out.println(lol);

			String msg = "line one\nline two\nl3\nl4";
			/*for (int k = 0; k < msg.length; k++ ) {
				if ()
			}*/
			//System.out.println("test");
			int index = 0;
			String edit = "";

			System.out.println("***old " + msg);

			/*while( (index = msg.indexOf("\n")) != -1){
				edit += msg.substring(0,index);
				edit += "nl_c";
				edit += msg.substring(index+1,msg.length());
				msg = edit;
			}*/
			msg = "_start_" + msg + "_end_";

			System.out.println("***new " + msg);
			os.println(msg);


		}
		catch (Exception e){
			System.err.println(e);
		}
		//end

		/*
		* If every thing has been initialized then we want to write some data to the
		* socket we have opened a connection to on the port portNumber .
		*/
		if(clientSocket != null && os != null && is != null){
			try{
				/* Create a thread to read from the server. */
				new Thread (new MultiThreadChatClient()).start();
				while(!closed){
					os.println(inputLine.readLine().trim());
				}
				/*
				* Close the output stream , close the input stream, close the socket .
				*/
				os.close();
				is.close();
				clientSocket.close();
			}
			catch(IOException e){
				System.err.println("IOException : " + e);
			}
		}
	}


	/*
	* Create a thread to read from the server.(Javadoc )
	*
	* @see java.lang.Runnable#run( )
	*/
	public void run(){

		/*
		* Keep on reading from the socket till we receive from the
		* server. Once we received that then we want to break.
		*/
		String responseLine;
		try{
			while((responseLine = is.readLine()) != null){
				System.out.println(responseLine);
				if(responseLine.indexOf( "* * * Bye ") != -1){
					break;
				}
			}
			closed = true;
		}
		catch(IOException e){
			System.err.println("IOException : " + e);
		}
	}
}
