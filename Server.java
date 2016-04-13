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
import java.security.spec.EncodedKeySpec;


/*
* A chat server that delivers public and private messages .
*/
public class Server{
	// The server socket .
	private ServerSocket serverSocket = null;

	// The client socket .
	private Socket clientSocket = null;

	public Server() {
		setupServer();
	}

	/**
	 * Sets up the server for incoming messages from client
	 */
	public void setupServer () {
		// The default port number.
		int portNumber = 2222;
		System.out.println("_.:SERVER DETAILS:._");
		System.out.println("\t\tIP: Type ifconfig for details or see below");
		System.out.println("\t\tPort: 2222");
		System.out.println("\t\tHosts picked up on machine:");
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
  }

	public static void main(String args[]){
		Server S = new Server();
	}//main
}//class


/**
 * Handles the receiving and decryption of messages sent from the client
 */
class clientThread {

	private String clientName = null;
	private DataInputStream is = null;
	private DataOutputStream os = null;
	private Socket clientSocket = null;
	private InetAddress address;//address that holds the IP
	private PrivateKey KRS;
	private byte[] KRSA = {48,-126,2,117,2,1,0,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,4,-126,2,95,48,-126,2,91,2,1,0,2,-127,-127,0,-91,98,35,43,-58,-114,-2,-8,90,111,-46,-127,46,102,36,-1,37,89,-15,54,71,119,-38,-62,90,106,-27,-87,-127,111,124,-96,24,67,-95,-4,-117,78,-98,71,-66,-6,120,17,-103,44,41,-59,79,38,-72,89,47,-90,-66,-50,-117,35,56,104,-16,-91,-94,51,-99,-64,89,-31,47,-65,-92,71,-10,91,67,-79,-44,94,79,100,-100,-6,75,-5,-31,-51,-73,-44,-124,60,-45,32,115,-65,-71,4,-122,-54,-43,37,-33,-81,62,-26,-126,-15,-123,-89,-103,-23,56,11,116,4,43,24,-75,-124,3,124,-42,-99,1,-31,15,53,32,-53,2,3,1,0,1,2,-127,-128,23,17,66,32,-105,-8,87,-3,-31,-9,88,-32,37,-51,-97,121,107,7,73,-118,-83,-101,61,11,0,-69,-118,63,3,75,-66,-111,65,-15,37,5,-23,-108,84,-91,99,48,-30,80,106,17,-21,-35,-106,117,-85,30,-35,115,-97,-121,-123,-122,-85,22,-112,2,58,70,72,-51,14,67,80,-21,-9,122,62,-11,-35,50,99,-8,-126,55,48,-1,-66,105,73,5,97,71,121,-64,-85,-66,16,-109,-87,4,-37,103,123,-32,16,115,-109,-7,-3,56,51,-23,121,67,-90,-84,-42,-123,-88,-86,-87,59,12,-52,9,-16,123,-66,43,-115,65,81,2,65,0,-19,91,102,-24,-21,27,-114,110,49,-36,91,1,-18,-17,45,-89,80,-126,17,76,123,-4,62,-61,45,-68,-102,-5,43,99,57,-76,70,14,19,30,99,-4,-17,23,-92,105,126,15,74,1,109,-51,45,-32,3,91,16,-102,-59,-91,124,-18,-107,-4,123,-110,111,115,2,65,0,-78,95,-118,-50,100,-6,-57,-97,-13,-103,37,87,29,14,101,25,-3,-44,-36,78,31,50,-127,20,-42,116,106,65,85,-34,37,-97,-15,-7,-51,112,-79,0,90,3,-89,-115,2,-48,-89,-106,118,-109,-102,15,116,40,-53,-4,-76,106,49,7,-53,-25,-11,7,3,73,2,64,90,-25,-62,-58,58,37,87,-85,-124,-107,44,-107,-44,-8,-19,-73,66,-14,77,-59,-55,70,-106,-109,18,21,70,22,36,75,-32,113,-42,-46,-43,39,-78,-117,-48,-42,113,53,-91,-2,29,13,-25,11,-54,34,29,-90,-26,-7,31,-15,125,-93,-78,-11,-4,45,-35,89,2,64,107,65,-24,69,-109,-110,-8,-42,-59,-76,33,47,-16,-40,-25,18,105,-1,-59,57,116,-88,-7,-43,125,-33,34,-59,-122,-52,-67,-13,31,-98,6,90,-19,20,57,12,89,-124,1,93,86,104,-77,-124,-83,-18,-4,-6,75,46,-7,-115,-95,77,-2,-34,-52,8,27,-127,2,64,33,-3,-110,-127,-45,102,3,44,-123,86,-108,-15,-97,-24,-40,115,51,108,35,102,100,-118,-48,37,26,76,-73,46,30,-106,-99,102,-37,-31,-61,-32,-91,-73,-110,-41,-1,56,-25,57,41,106,119,77,46,47,92,45,48,14,54,-73,-93,-41,-108,-122,-16,-110,-55,-34};
	private byte[] KUSA = {48,-127,-97,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-127,-115,0,48,-127,-119,2,-127,-127,0,-91,98,35,43,-58,-114,-2,-8,90,111,-46,-127,46,102,36,-1,37,89,-15,54,71,119,-38,-62,90,106,-27,-87,-127,111,124,-96,24,67,-95,-4,-117,78,-98,71,-66,-6,120,17,-103,44,41,-59,79,38,-72,89,47,-90,-66,-50,-117,35,56,104,-16,-91,-94,51,-99,-64,89,-31,47,-65,-92,71,-10,91,67,-79,-44,94,79,100,-100,-6,75,-5,-31,-51,-73,-44,-124,60,-45,32,115,-65,-71,4,-122,-54,-43,37,-33,-81,62,-26,-126,-15,-123,-89,-103,-23,56,11,116,4,43,24,-75,-124,3,124,-42,-99,1,-31,15,53,32,-53,2,3,1,0,1};
	private byte[] KUCA = {48,-127,-97,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-127,-115,0,48,-127,-119,2,-127,-127,0,-122,-53,-74,-87,-87,-99,124,-105,-120,-1,0,-67,-71,93,-90,112,109,30,30,5,-107,-97,61,16,74,86,112,-36,-44,-38,85,-128,4,3,98,86,99,8,-20,-96,57,-79,-59,-103,-3,-41,93,58,-99,-94,-36,63,28,70,0,-80,23,125,-66,-34,-18,116,122,77,45,-6,-30,-38,-73,-80,71,88,54,125,-87,-110,41,-86,-59,-31,79,-15,-5,78,122,-115,-43,116,-113,16,1,97,-20,-47,-66,-75,32,23,117,50,-2,11,-26,88,18,-77,27,-38,-44,63,95,66,-104,113,90,-116,-73,-58,-17,-78,67,126,-27,-63,-38,23,68,93,2,3,1,0,1};
	private byte[] ivSpecStored = {58,66,-52,-59,-122,-124,84,-35,-6,-11,-44,-106,42,-121,32,48};
	private PublicKey KUS;
	private PublicKey KUC;
	private SecretKey secretKey = null;
	private SecretKeySpec sk = null;

	/**
	 * Parameterized contructor that sets up the socket connection between server and client
	 * @param clientSocket The client's socket that the server accepts
	 */
	public clientThread(Socket clientSocket){
		this.clientSocket = clientSocket;
		this.address = this.clientSocket.getInetAddress();//get the address from the connecting client
		startServer();
	}

	/**
	 * Creates input and output streams for the communication between client and server
	 */
	public void createIOStreams () {
		try {
			is = new DataInputStream(clientSocket.getInputStream());
			os = new DataOutputStream(clientSocket.getOutputStream());
			String name = "user";

			System.out.println("\n\n_.:INCOMING CONNECTION ACCEPETED FROM " + clientSocket.getInetAddress() + ":._");
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	/**
	*creating keys from stored bytes
	*/
	public void createStoredKeys(){
		try {
			//create server keys from stored bytes
			KUS = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(KUSA));
			KUC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(KUCA));
			KRS= KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(KRSA));
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	/**
	 * Generates the Server's public/private key pair (KRS, KUS)
	 */
	public void generateKeys() {
		try {
			KRS = null;
			//create server's assymmetric keys
			System.out.println("\n\n_.:CREATING SERVERS PRIVATE AND PUBLIC KEYS:._");
			/*KeyPairGenerator keyGen2 = KeyPairGenerator.getInstance("RSA");
			keyGen2.initialize(1024);
			KeyPair serverkeys = keyGen2.generateKeyPair();
			//get keys
			KRS = serverkeys.getPrivate();
			KUS = serverkeys.getPublic();

			System.out.println("**********************");
			for (int i = 0; i < KRS.getEncoded().length;i++ ) {
				System.out.print(KRS.getEncoded()[i]+",");
			}
			System.out.println("**********************");
			for (int i = 0; i < KUS.getEncoded().length;i++ ) {
				System.out.print(KUS.getEncoded()[i]+",");
			}



			System.out.println("\n\t_.:EXPORTING SERVERS PUBLIC KEY:._");
			System.out.println("\t\tWriting public key to file \"server_public_key.txt\"");*/
			createStoredKeys();
			//Write KUS to textfile server_public_key.txt
			byte[] KUSArray = KUS.getEncoded();
			FileOutputStream fos = new FileOutputStream("server_public_key.txt");
			fos.write(KUSArray);
			fos.close();
			int count1 = 0;
			for (int i = 0; i < KUSArray.length; i++){
				count1 += KUSArray[i];
			}
			System.out.println("\t\tServer's Public Key summation: " + count1);
			System.out.println("\n_.:SERVERS PRIVATE AND PUBLIC KEYS CREATED:._");
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	/**
	 * Receive message from CLIENT
	 * @return	byte[] message	the message sent from the client
	 */
	public byte[] receiveMessage() {
		byte[] message = null;
		try {
			System.out.println("\n\n_.:WAITING FOR CLIENT:._");
			int msgLength = is.readInt();
			System.out.println("\n\n_.:RECEIVING PACKET FROM CLIENT:._");
			System.out.println("\t_.:PACKET DETAILS:._");
			System.out.println("\t\tSize of arriving packet: " + msgLength);

			if (msgLength >0){
				message = new byte[msgLength];
				is.readFully(message, 0, message.length);
			}else{
				return null;
			}
			int count2 = 0;
			for (int i = 0; i < message.length; i++){
				count2 += message[i];
			}
			System.out.println("\t\tReceived Packet summation: " + count2);

			System.out.println("\n_.:PACKET FULLY RECEIVED FROM CLIENT:._");

		}
		catch (Exception e) {
			System.err.println(e);
		}
		return message;
	}

	/**
	 * Gets the encrypted shared key (E_(KUS){Ks})
	 * @param	byte[] message	the message sent from client
	 * @return	byte[] keyPart	the encrypted shared key
	 */
	public byte[] getEncrptedKeyPart(byte[] message) {
		byte[] keyPart = new byte[128];
		try {
			//add provider
			Security.addProvider(new BouncyCastleProvider());
			//do crypto stuff here
			System.out.println("\n\n_.:UNPACKING PACKET:._");

			System.out.println("\n\t_.:SPLITTING UP RECEIVED PACKET:._");
			//split up packet


			for(int i = 0; i < 128; i++){
				keyPart[i] = message[i];
			}

			int count4 = 0;
			for (int i = 0; i < keyPart.length; i++){
				count4 += keyPart[i];
			}
			System.out.println("\t\tEncrypted Shared Key summation: " + count4);
		}
		catch (Exception e) {
			System.err.println(e);
		}

		return keyPart;
	}

	/**
	 * Gets the ciphertext E_(Ks){Z(DS + P)} from message
 	 * @param	byte[] message	the message sent from client
 	 * @return	byte[] crypPart	the encrypted and compressed payload
	 */
	public byte[] getEncryptedMessagePart(byte[] message) {
		byte[] crypPart = new byte[message.length-128];
		try {

			//we know the encrypted key is 128bits

			//rest is the encrypted message
			for(int j = 128, k = 0; j < message.length; j++, k++){
				crypPart[k] = message[j];
			}

			int count5 = 0;
			for (int i = 0; i < crypPart.length; i++){
				count5 += crypPart[i];
			}
			System.out.println("\t\tEncrypted Compressed Packet summation: " + count5);
			System.out.println("\n_.:PACKET UNPACKED:._");
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return crypPart;
	}

	/**
	 * Decrypts the shared key using KRS
	 * @param	byte[] keyPart E_(KUS){Ks} (ensuring confidentiality)
	 */
	public void decryptSharedKey (byte[] keyPart) {

		try {
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
			System.out.println("\t\tShared Key summation: " + count6);

			//reconstruct shared key
			secretKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
			sk = new SecretKeySpec(secretKey.getEncoded(), "AES");
			System.out.println("\t\tShared Key constructed");
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	/**
	 * Decrypts the ciphertext E_(Ks){Z(DS + P)} using Ks (ensuring confidentiality)
	 * @param	byte[] crypPart			the encrypted and compressed payload
	 * @return	byte[] decryptedPackage	Z(DS + P)
	 */
	public byte[] decryptMessage (byte[] crypPart) {
		byte[] decryptedPackage = null;
		try {
			System.out.println("\n\t_.:DECRYPTING COMPRESSED MESSAGE:._");

			//get iv for decryption
			/*System.out.println("\t\tReading in IV from file \"client_iv.txt\"");
			Path path2 = Paths.get("client_iv.txt");
			byte[] iv = Files.readAllBytes(path2);*/

			int count7 = 0;
			for (int i = 0; i < ivSpecStored.length; i++){
				count7 += ivSpecStored[i];
			}
			System.out.println("\t\tIV summation: " + count7);

			//we decrypt the packet with the iv and the shared key


			Cipher aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aescipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(ivSpecStored));
			decryptedPackage = aescipher.doFinal(crypPart);

			int count8 = 0;
			for (int i = 0; i < decryptedPackage.length; i++){
				count8 += decryptedPackage[i];
			}
			System.out.println("\t\tCompressed Packet summation: " + count8);

			System.out.println("\n_.:CONFIDENTIALITY ENSURED:._");
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return decryptedPackage;
	}

	/**
	 * Decompresses payload
	 * @param	byte[] decryptedPackage	Z(DS + P)
	 * @return	byte[] authMessage		DS + P (digital signature + plaintext)
	 */
	public byte[] decompressMessage (byte[] decryptedPackage) {
		byte[] result = new byte[1024];
		byte[] authMessage = null;
		try {
			//AUTHENTICAION
			System.out.println("\n\n_.:ENSURING AUTHENTICITY:._");

			System.out.println("\n\t_.:DECROMPESSING PACKAGE:._");

			//create inflater
			Inflater decompresser = new Inflater();
			decompresser.setInput(decryptedPackage, 0, decryptedPackage.length);

			//read out values
			ByteArrayOutputStream o2 = new ByteArrayOutputStream(decryptedPackage.length);
			while(!decompresser.finished()){
				int count = decompresser.inflate(result);
				o2.write(result,0,count);
			}
			o2.close();
			authMessage = o2.toByteArray();
			decompresser.end();

			int count9 = 0;
			for (int i = 0; i < authMessage.length; i++){
				count9 += authMessage[i];
			}
			System.out.println("\t\tUncompressed packet summation: " + count9);
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return authMessage;
	}

	/**
	 * Gets the digital signature DS from the authenticated message (DS + P)
	 * @param	byte[] authMessage	DS + P (digital signature + plaintext)
	 * @return	byte[] sigPart		DS
	 */
	public byte[] getSignaturePart (byte[] authMessage) {
		System.out.println("\n\t_.:SPLITTING UNCOMPRESSED MESSAGE:._");
		//authMessage is decompressed message
		byte[] sigPart = new byte[128];
		try {
			System.out.println("\t\tSplitting off signature");
			//signature is 128 bytes as we encrypted with private key
			for(int i = 0; i < 128; i++){
				sigPart[i] = authMessage[i];
			}
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return sigPart;
	}

	/**
	 * Gets the plaintext P from the authenticated message (DS + P)
	 * @param	byte[] authMessage	DS + P (digital signature + plaintext)
	 * @return	byte[] plaintext	P
	 */
	public byte[] getPlaintext (byte[] authMessage) {
		byte[] plaintext = new byte[authMessage.length-128];
		try {
			System.out.println("\t\tSplitting off Plaintext");

			//rest is the plain text
			for(int j = 128, k = 0; j < authMessage.length; j++, k++){
				plaintext[k] = authMessage[j];
			}

			//create message
			System.out.println("\t\tReconstructing Plaintext");
			System.out.println("\t\tPlaintext reads: ");
			System.out.println("\t\t________________________________________________________");
			System.out.println("\t\t" + new String(plaintext) );
			System.out.println("\t\t________________________________________________________");
			System.out.println("\t\tMessage End");

		}
		catch (Exception e) {
			System.err.println(e);
		}
		return plaintext;
	}

	/**
	 * genreates the hash of the received plaintext to be compared with the received hash (for authentication)
	 * @param	byte[] plaintext	original text from client
	 * @return	byte[] digest		the hash H_S(P) (using SHA-256)
	 */
	public byte[] generatePlaintextHash (byte[] plaintext) {
		byte[] digest = null;
		try {
			System.out.println("\n\t_.:CONFIRMING AUTHENTICITY:._");
			//create hash of the message to check signature
			System.out.println("\t\tMaking own Message Digest of Plaintext");

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(plaintext);
			digest = md.digest();

			int count10 = 0;
			for (int i = 0; i < digest.length; i++){
				count10 += digest[i];
			}
			System.out.println("\t\tReconstructed Message Digest summation: " + count10);
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return digest;
	}

	/**
	 * acquires the client's public key to decrypt the digital signature (for authentication)
	 */
	public void getKUC () {
		/*try {
			System.out.println("\t\tReading in clients public key from \"client_public_key.txt\"");
			//GET CLEINT PUBLIC KEY KUC
			Path path = Paths.get("client_public_key.txt");
			byte [] CKey = Files.readAllBytes(path);
			//generate public key from bytes
			KUC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(CKey));
			int count3 = 0;
			for (int i = 0; i < CKey.length; i++){
				count3 += CKey[i];
			}
			System.out.println("\t\tClients Public Key summation: " + count3);
		}
		catch (Exception e) {
			System.err.println(e);
		}*/
	}

	/**
	 * Decrypts the hash
	 * @param	byte[] sigPart		E_(KRC){H_C(P)}
	 * @return byte[] decryptedHash	H_C(P) (received from client)
	 */
	public byte[] decryptHash (byte[] sigPart) {
		//decrypt signed hash with public key
		byte[] decryptedHash = null;
		try {
			Cipher hashCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			hashCipher.init(Cipher.DECRYPT_MODE, KUC);
			decryptedHash = hashCipher.doFinal(sigPart);

			int count11 = 0;
			for (int i = 0; i < decryptedHash.length; i++){
				count11 += decryptedHash[i];
			}
			System.out.println("\t\tDecrypted Message Digest summation: " + count11);
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return decryptedHash;
	}

	/**
	 * Compares the received and generated hashes and if they are the same then the server can verify the authenticity
	 * of the digital signature. Thus the server knows the message was indeed sent from the client.
	 * @param  byte[] decryptedHash	H_C(P) (received from client)
	 * @param  byte[] digest		H_S(P) (generated by server)
	 */
	public void authenticate (byte[] decryptedHash, byte[] digest) {
		try {
			System.out.println("\t\tChecking if Authenticity was achieved");

			if (Arrays.equals(decryptedHash,digest)){
				System.out.println("\t\tAuthenticity was achieved");
			}else{
				System.out.println("\t\tAuthenticity was not achieved! DONT TRUST THIS MESSAGE!");
			}
			System.out.println("\n_.:AUTHENTICITY ENSURED:._");
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	public void startServer(){
		try {
			createIOStreams();
			generateKeys();

			while (true){
				byte[] recEncryptedMessage = receiveMessage();
				if (recEncryptedMessage == null){
					break;
				}
				byte[] encryptedKey = getEncrptedKeyPart(recEncryptedMessage);
				byte[] encPayload = getEncryptedMessagePart(recEncryptedMessage);
				decryptSharedKey(encryptedKey);
				byte[] compPayload = decryptMessage(encPayload);
				byte[] payload = decompressMessage(compPayload);
				byte[] signature = getSignaturePart(payload);
				byte[] plaintext = getPlaintext(payload);
				byte[] plaintextHash = generatePlaintextHash(plaintext);
				getKUC();
				byte[] recMessageHash = decryptHash(signature);
				authenticate(recMessageHash, plaintextHash);
			}

			/*
			* close the output stream , close the input stream , close the socket .
			*/
			is.close();
			os.close();
			clientSocket.close();



		}
		catch(IOException e){
			System.err.println(e);
		}
		System.out.println("\n\n_.:CLIENT CLOSED CONNECTION:._");
		System.out.println("\n\n_.:SERVER SHUTTING DOWN:._");
	}
}//class
