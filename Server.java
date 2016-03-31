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
import java.net.NetworkInterface;


/*
* A chat server that delivers public and private messages .
*/
public class Server{
	// The server socket .
	private static ServerSocket serverSocket = null;

	// The client socket .
	private static Socket clientSocket = null;


	public static void main(String args[]){
		// The default port number.
		int portNumber = 2222;
		System.out.println("_.:SERVER DETAILS:._");
		System.out.println("\t\tIP: Type ifconfig for details or see below");
		System.out.println("\t\tPort: 2222");
		System.out.println("\t\tHosts picked up on machine:");
		//get all IP addresses on machine to help client connect
		try{
			Enumeration enumer = NetworkInterface.getNetworkInterfaces();
			while(enumer.hasMoreElements()){
			    NetworkInterface n = (NetworkInterface) enumer.nextElement();
			    Enumeration ee = n.getInetAddresses();
			    while (ee.hasMoreElements())
			    {
			        InetAddress i = (InetAddress) ee.nextElement();
					if (!i.isLoopbackAddress() && !i.isMulticastAddress() && !i.isLinkLocalAddress()){
						System.out.println("\t\t" + i.getHostAddress());
					}

			    }
			}
		}
		catch (Exception e){
			System.out.println("Exception: " + e);
		}



		System.out.println("_.:SERVER DETAILS:._");

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
		* Create a client socket */
		clientThread client = null;

		try{
			clientSocket = serverSocket.accept();
			client = new clientThread(clientSocket);
		}
		catch(IOException e){
			System.out.println("IOException Error" + e);
		}
		System.out.println("\n\n_.:SERVER SHUT DOWN:._");

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
	private InetAddress address;//address that holds the IP


	public clientThread(Socket clientSocket){
		this.clientSocket = clientSocket;
		this.address = this.clientSocket.getInetAddress();//get the address from the connecting client
		startServer();
	}


	public void startServer(){
		try{
			/*
			* Create input and output streams for this client.
			*/
			is = new DataInputStream(clientSocket.getInputStream());
			os = new DataOutputStream(clientSocket.getOutputStream());
			String name = "user";

			System.out.println("\n\n_.:INCOMING CONNECTION ACCEPETED FROM " + clientSocket.getInetAddress() + ":._");

			PrivateKey KRS = null;
			//create server's assymmetric keys
			try{
				System.out.println("\n\n_.:CREATING SERVERS PRIVATE AND PUBLIC KEYS:._");
				KeyPairGenerator keyGen2 = KeyPairGenerator.getInstance("RSA");
				keyGen2.initialize(1024);
				KeyPair serverkeys = keyGen2.generateKeyPair();
				//get keys
				KRS = serverkeys.getPrivate();
				PublicKey KUS = serverkeys.getPublic();

				System.out.println("\n\t_.:EXPORTING SERVERS PUBLIC KEY:._");
				System.out.println("\t\t Writing public key to file \"server_public_key.txt\"");
				//Write KUS to textfile server_public_key.txt
				byte[] KUSArray = KUS.getEncoded();
				FileOutputStream fos = new FileOutputStream("server_public_key.txt");
				fos.write(KUSArray);
				fos.close();
				int count1 = 0;
				for (int i = 0; i < KUSArray.length; i++){
					count1 += KUSArray[i];
				}
				System.out.println("\t\tServer's Public Key Summation: " + count1);
				System.out.println("\n_.:SERVERS PRIVATE AND PUBLIC KEYS CREATED:._");
			}
			catch (Exception e){
				System.out.println("Exception: " + e);
			}
			while(true){
				System.out.println("\n\n_.:WAITING FOR CLIENT:._");
				int msgLength = is.readInt();
				System.out.println("\n\n_.:RECEIVING PACKET FROM CLIENT:._");
				System.out.println("\t_.:PACKET DETAILS:._");
				System.out.println("\t\tSize of arriving packet: " + msgLength);
				byte[] message = null;
				if (msgLength > 0){
					message = new byte[msgLength];
					is.readFully(message, 0, message.length);
				}
				else{
					break;
				}
				int count2 = 0;
				for (int i = 0; i < message.length; i++){
					count2 += message[i];
				}
				System.out.println("\t\tReceived Packet Summation: " + count2);

				System.out.println("\n_.:PACKET FULLY RECEIVED FROM CLIENT:._");


				try{


					//add provider
					Security.addProvider(new BouncyCastleProvider());
					//do crypto stuff here
					System.out.println("\n\n_.:UNPACKING PACKET:._");

					System.out.println("\n\t_.:SPLITTING UP RECEIVED PACKET:._");
					//split up packet
					byte[] keyPart = new byte[128];
					byte[] crypPart = new byte[message.length-128];
					//we know the encrypted key is 128bits
					for(int i = 0; i < 128; i++){
						keyPart[i] = message[i];
					}
					//rest is the encrypted message
					for(int j = 128, k = 0; j < message.length; j++, k++){
						crypPart[k] = message[j];
					}

					int count4 = 0;
					for (int i = 0; i < keyPart.length; i++){
						count4 += keyPart[i];
					}
					System.out.println("\t\tEncrypted Shared Key Summation: " + count4);

					int count5 = 0;
					for (int i = 0; i < crypPart.length; i++){
						count5 += crypPart[i];
					}
					System.out.println("\t\tEncrypted Compressed Packet Summation: " + count5);
					System.out.println("\n_.:PACKET UNPACKED:._");


					//CONFIDENTIALITY
					System.out.println("\n\n_.:ENSURING CONFIDENTIALITY:._");
					System.out.println("\n\t_.:DECRYPTING SHARED KEY:._");




					//decrypt shared key with the public key of client
					byte[] decryptedKey = null;
					Cipher packet = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					packet.init(Cipher.DECRYPT_MODE, KRS);
					decryptedKey = packet.doFinal(keyPart);

					int count6 = 0;
					for (int i = 0; i < decryptedKey.length; i++){
						count6 += decryptedKey[i];
					}
					System.out.println("\t\tShared Key Summation: " + count6);


					//decrypt zip message with shared key
					//reconstruct shared key
					SecretKey secretKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
					SecretKeySpec sk = new SecretKeySpec(secretKey.getEncoded(), "AES");
					System.out.println("\t\tShared Key constructed");

					System.out.println("\n\t_.:DECRYPTING COMPRESSED MESSAGE:._");

					//get iv for decryption
					System.out.println("\t\tReading in IV from file \"client_iv.txt\"");
					Path path2 = Paths.get("client_iv.txt");
					byte[] iv = Files.readAllBytes(path2);

					int count7 = 0;
					for (int i = 0; i < iv.length; i++){
						count7 += iv[i];
					}
					System.out.println("\t\tIV Summation: " + count7);

					//we decrypt the packet with the iv and the shared key

					byte[] decryptedPackage = null;
					Cipher aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
					aescipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
					decryptedPackage = aescipher.doFinal(crypPart);

					int count8 = 0;
					for (int i = 0; i < decryptedPackage.length; i++){
						count8 += decryptedPackage[i];
					}
					System.out.println("\t\tCompressed Packet Summation: " + count8);

					System.out.println("\n_.:CONFIDENTIALITY ENSURED:._");
					//AUTHENTICAION
					System.out.println("\n\n_.:ENSURING AUTHENTICITY:._");

					System.out.println("\n\t_.:DECROMPESSING PACKAGE:._");

					//create inflater
					Inflater decompresser = new Inflater();
					decompresser.setInput(decryptedPackage, 0, decryptedPackage.length);
					byte[] result = new byte[1024];
					//read out values
					ByteArrayOutputStream o2 = new ByteArrayOutputStream(decryptedPackage.length);
					while(!decompresser.finished()){
						int count = decompresser.inflate(result);
						o2.write(result,0,count);
					}
					o2.close();
					byte[] op2 = o2.toByteArray();
					decompresser.end();

					int count9 = 0;
					for (int i = 0; i < op2.length; i++){
						count9 += op2[i];
					}
					System.out.println("\t\tUncompressed packet Summation: " + count9);


					System.out.println("\n\t_.:SPLITTING UNCOMPRESSED MESSAGE:._");
					//op2 is decompressed message
					byte[] sigPart = new byte[128];
					byte[] messagePart = new byte[op2.length-128];
					System.out.println("\t\tSplitting off Signature");
					System.out.println("\t\tSplitting off Plaintext");
					//signature is 128 bytes as we encrypted with private key
					for(int i = 0; i < 128; i++){
						sigPart[i] = op2[i];
					}
					//rest is the plain text
					for(int j = 128, k = 0; j < op2.length; j++, k++){
						messagePart[k] = op2[j];
					}

					int count14 = 0;
					for (int i = 0; i < sigPart.length; i++){
						count14 += sigPart[i];
					}
					System.out.println("\t\tEncrypted Hash Summation: " + count14);

					//create message
					System.out.println("\t\tReconstructing Plaintext");
					System.out.println("\t\tPlaintext reads: ");
					System.out.println("\t\t________________________________________________________");
					String origMessage = new String(messagePart);
					System.out.println("\t\t" + origMessage );
					System.out.println("\t\t________________________________________________________");
					System.out.println("\t\tMessage End");

					System.out.println("\n\t_.:CONFIRMING AUTHENTICITY:._");
					//create hash of the message to check signature
					System.out.println("\t\tMaking own Message Digest of Plaintext");
					byte[] digest = null;
					MessageDigest md = MessageDigest.getInstance("SHA-256");
					md.update(messagePart);
					digest = md.digest();

					int count10 = 0;
					for (int i = 0; i < digest.length; i++){
						count10 += digest[i];
					}
					System.out.println("\t\tReconstructed Message Digest Summation: " + count10);

					System.out.println("\t\tReading in clients public key from \"client_public_key.txt\"");
					//GET CLEINT PUBLIC KEY KUC
					Path path = Paths.get("client_public_key.txt");
					byte [] CKey = Files.readAllBytes(path);
					//generate public key from bytes
					PublicKey KUC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(CKey));
					int count3 = 0;
					for (int i = 0; i < CKey.length; i++){
						count3 += CKey[i];
					}
					System.out.println("\t\tClients Public Key Summation: " + count3);

					//decrypt signed hash with public key
					byte[] decryptedHash = null;
					Cipher hashCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					hashCipher.init(Cipher.DECRYPT_MODE, KUC);
					decryptedHash = hashCipher.doFinal(sigPart);

					int count11 = 0;
					for (int i = 0; i < decryptedHash.length; i++){
						count11 += decryptedHash[i];
					}
					System.out.println("\t\tDecrypted Message Digest Summation: " + count11);
					System.out.println("\t\tChecking if Authenticity was achieved");

					if (Arrays.equals(decryptedHash,digest)){
						System.out.println("\t\tAuthenticity was achieved");
					}else{
						System.out.println("\t\tAuthenticity was not achieved! DONT TRUST THIS MESSAGE!");
					}
					System.out.println("\n_.:AUTHENTICITY ENSURED:._");


				}

				catch (Exception e){
					System.err.println("Exception: " + e);
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
		System.out.println("\n\n_.:CLIENT CLOSED CONNECTION:._");
		System.out.println("\n\n_.:SERVER SHUTTING DOWN:._");
	}
}//class
