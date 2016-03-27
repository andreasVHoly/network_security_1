import java.io.DataInputStream;
import java.io.PrintStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.*;

//newly added

import javax.xml.bind.DatatypeConverter;

import java.util.zip.*;//for zipping
import javax.crypto.*;//for crypto
import java.security.*;//for crypto
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
		String message = "This is what we want to encrypt";

		//create hash of the message
		byte[] digest = null;
		byte[] signedMessage = null;
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(message.getBytes("UTF-8"));
			digest = md.digest();



			//create private and public keys for client

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keys = keyGen.generateKeyPair();

			PrivateKey KRC = keys.getPrivate();
			PublicKey KUC = keys.getPublic();

			//sign hash with private key
			byte[] encryptedHash = null;
			Cipher RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			RSAcipher.init(Cipher.ENCRYPT_MODE, KRC);
			encryptedHash = RSAcipher.doFinal(digest);


			//String privateKey = new String(Base64.encodeBase64(KRC.getEncoded(), 0,KRC.getEncoded().length, Base64.NO_WRAP));
			//String publicKey = new String(Base64.encode(KUC.getEncoded(), 0,KUC.getEncoded().length, Base64.NO_WRAP));
			System.out.println("Client Private Key Algorithm " + KRC.getAlgorithm());
			System.out.println("Client Private Key " + KRC);
			System.out.println("Client Public Key Algorithm " + KUC.getAlgorithm());
			System.out.println("Client Public Key " + KUC);


			//concantenate hash and original message TODO



			//zip the above TODO



			//encrypt the zip with shared key TODO

			//create shared key
			//PGPSecretKey


			//create cipher for encryption
			/*byte[] encryptedHash = null;
			Cipher aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aescipher.init(Cipher.ENCRYPT_MODE, );//need shared key here TODO
			encryptedHash = aescipher.doFinal(digest);*/


			//encrypt shared key with public key of server TODO
			/*byte[] encryptedHash = null;
			Cipher RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			RSAcipher.init(Cipher.ENCRYPT_MODE, ); TODO we need the public key of server here
			encryptedHash = RSAcipher.doFinal(digest);*/

			//concat the encrypyted shared key and the encrypted zip TODO


			//send off TODO
			//os.println(data);


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
