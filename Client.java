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
//new bouncy castle libs
import org.bouncycastle.openpgp.PGPPrivateKey;//pgp crypto
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.spec.EncodedKeySpec;


public class Client{
	private int portNumber;
	private String host;
	private Scanner clientIn;
	//The client socket
	private Socket clientSocket = null;
	// The output stream
	private DataOutputStream os = null;
	// The input stream
	private DataInputStream is = null ;
	private BufferedReader inputLine = null;
	private boolean closed = false; //Volatile variable?
	private PrivateKey KRC;
	private PublicKey KUC;
	private byte[] KRCA = {48,-126,2,118,2,1,0,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,4,-126,2,96,48,-126,2,92,2,1,0,2,-127,-127,0,-122,-53,-74,-87,-87,-99,124,-105,-120,-1,0,-67,-71,93,-90,112,109,30,30,5,-107,-97,61,16,74,86,112,-36,-44,-38,85,-128,4,3,98,86,99,8,-20,-96,57,-79,-59,-103,-3,-41,93,58,-99,-94,-36,63,28,70,0,-80,23,125,-66,-34,-18,116,122,77,45,-6,-30,-38,-73,-80,71,88,54,125,-87,-110,41,-86,-59,-31,79,-15,-5,78,122,-115,-43,116,-113,16,1,97,-20,-47,-66,-75,32,23,117,50,-2,11,-26,88,18,-77,27,-38,-44,63,95,66,-104,113,90,-116,-73,-58,-17,-78,67,126,-27,-63,-38,23,68,93,2,3,1,0,1,2,-127,-128,79,-28,-42,115,97,49,18,-13,-50,35,54,-111,61,25,32,-39,106,19,123,-65,-37,-102,-14,90,-127,117,18,-104,17,33,7,-92,68,-68,-84,-64,127,26,127,5,-56,-84,113,110,-128,97,-15,-60,24,66,-69,64,60,-59,-47,10,-114,33,-35,-53,-52,-110,5,26,115,85,-31,60,-55,-101,-61,-95,43,-108,30,-93,-102,-11,-79,118,0,-30,-60,-124,112,-61,-55,-23,13,-61,-43,-44,-22,31,91,-58,-76,42,-105,38,114,-56,98,-113,-26,83,-61,88,83,29,82,94,67,-86,103,-115,36,-46,-102,73,-84,3,-41,124,-48,-22,21,1,2,65,0,-43,-97,68,-24,-90,-24,27,-27,99,-60,-48,2,-95,-83,-24,26,-2,122,114,-109,-98,98,70,-67,50,-88,120,-54,-118,35,-18,-59,116,98,-64,57,29,127,109,94,61,9,-110,-10,-77,108,-118,-81,-120,40,-71,-69,-73,100,1,-41,-55,33,-36,-34,-101,7,-126,-111,2,65,0,-95,-119,69,-99,-94,-39,109,-73,81,3,98,-11,-30,62,0,-15,-126,-123,113,-92,100,43,97,-74,4,-59,-111,-89,-90,-86,21,44,-37,98,-50,30,82,-90,-119,27,-124,-21,8,109,-31,11,26,104,-27,-56,-77,2,82,115,-37,-6,112,-110,-68,-78,-108,102,-13,13,2,64,1,85,74,31,-51,-110,-37,65,-74,58,-81,53,-92,-2,-87,-39,41,71,104,89,-91,126,101,-124,-98,-63,80,103,-85,47,8,57,113,61,-128,-121,-102,-72,-123,-35,53,-78,78,-103,125,-117,42,-34,103,-110,33,126,-101,105,99,93,-114,98,-56,-73,22,-18,-104,17,2,64,31,92,-69,123,99,-122,-69,90,-128,12,28,70,-120,-22,104,-36,122,-18,-43,-91,-119,29,51,23,87,-51,-45,-3,-84,-54,16,-38,104,-83,-62,62,-8,-27,4,113,-89,88,-54,-122,42,-49,49,13,116,-81,-122,-79,-56,-72,93,-39,61,-55,-1,-128,-36,119,48,113,2,65,0,-115,-58,-84,127,39,46,33,117,-94,-102,18,-29,15,-99,-87,32,-53,49,11,35,31,-102,-15,-30,88,56,-27,-43,94,-44,25,-80,-102,23,-29,-74,-43,-11,-14,28,-25,106,93,12,59,48,117,-10,36,-15,125,100,-29,-102,103,-66,41,-65,-74,-35,10,19,104,21};
	private byte[] KUCA = {48,-127,-97,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-127,-115,0,48,-127,-119,2,-127,-127,0,-122,-53,-74,-87,-87,-99,124,-105,-120,-1,0,-67,-71,93,-90,112,109,30,30,5,-107,-97,61,16,74,86,112,-36,-44,-38,85,-128,4,3,98,86,99,8,-20,-96,57,-79,-59,-103,-3,-41,93,58,-99,-94,-36,63,28,70,0,-80,23,125,-66,-34,-18,116,122,77,45,-6,-30,-38,-73,-80,71,88,54,125,-87,-110,41,-86,-59,-31,79,-15,-5,78,122,-115,-43,116,-113,16,1,97,-20,-47,-66,-75,32,23,117,50,-2,11,-26,88,18,-77,27,-38,-44,63,95,66,-104,113,90,-116,-73,-58,-17,-78,67,126,-27,-63,-38,23,68,93,2,3,1,0,1};
	private byte[] KUSA = {48,-127,-97,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-127,-115,0,48,-127,-119,2,-127,-127,0,-91,98,35,43,-58,-114,-2,-8,90,111,-46,-127,46,102,36,-1,37,89,-15,54,71,119,-38,-62,90,106,-27,-87,-127,111,124,-96,24,67,-95,-4,-117,78,-98,71,-66,-6,120,17,-103,44,41,-59,79,38,-72,89,47,-90,-66,-50,-117,35,56,104,-16,-91,-94,51,-99,-64,89,-31,47,-65,-92,71,-10,91,67,-79,-44,94,79,100,-100,-6,75,-5,-31,-51,-73,-44,-124,60,-45,32,115,-65,-71,4,-122,-54,-43,37,-33,-81,62,-26,-126,-15,-123,-89,-103,-23,56,11,116,4,43,24,-75,-124,3,124,-42,-99,1,-31,15,53,32,-53,2,3,1,0,1};
	private byte[] ivSpecStored = {58,66,-52,-59,-122,-124,84,-35,-6,-11,-44,-106,42,-121,32,48};
	private SecretKey secretKey;
	private SecretKeySpec k;
	private PublicKey KUS;
	private Cipher aescipher;

	/*Default constructor.*/
	public Client () {
		// The default port.
		portNumber = 2222;
		// The default host.
		host = "localhost";

		clientIn = new Scanner(System.in);
		System.out.println("Please enter the server address: ");

		if(!host.equals("")){
			host = clientIn.nextLine();
		}


		socketSetup();
		//adding bouncy castle provider
		Security.addProvider(new BouncyCastleProvider());
		//default message
		// String plaintext = "This is what we want to encrypt!!!!!!!! This is a message we are testing";
		String plaintext = "";

		//get input from the user to get a message to decrypt
		System.out.println("Please enter a message to encrypt(/q to quit): ");
		if(!host.equals("")){
			plaintext = clientIn.nextLine();
		}
		//spacing
		System.out.println("\n");

		while(!plaintext.startsWith("/q")){
			byte[] hash = generateHash(plaintext);
			generateKeys();
			byte[] encryptedHash = encryptHash(hash);
			byte[] authMessage = authenticatePlaintext(encryptedHash, plaintext);
			byte[] compMessage = compressMessage(authMessage);
			generateSecretKey();
			byte[] ciphertext = generateCiphertext(compMessage);
			generateIV();
			getKUS();
			byte[] encryptedKey = encryptSecretKey();
			byte[] finCiphertext = generateFinalCiphertext(encryptedKey, ciphertext);
			sendMessage(finCiphertext);

			System.out.println("\nPlease enter a message to encrypt(/q to quit): ");
			if(!plaintext.equals("")){
				plaintext = clientIn.nextLine();
			}
		}

		System.out.println("\n_.:CLOSING CONNECTION TO SERVER:._");
		//to let server know we are breaking the connection
		try{
			os.writeInt(0);
			clientIn.close();
			is.close();
			os.close();
			clientSocket.close();
		}
		catch (Exception e){
			System.err.println("Exception: " + e);
		}
		System.out.println("\n_.:CONNECTION TO SERVER CLOSED:._");
	}

	/**
	 * Paramterized contructor that sets up chat connecting to a specific server.
	 * @param   String serverIP		Server's IP address
	 * @param   String host			The host port
	 */
	public Client (String serverIP, String host) {
		// The default port.
		portNumber = 2222;
		// The default host.
		host = host;

		//adding bouncy castle provider
		Security.addProvider(new BouncyCastleProvider());
		//default message
		String plaintext = "This is what we want to encrypt!!!!!!!! This is a message we are testing";

		createStoredKeys();
		//get input from the user to get a message to decrypt
		clientIn = new Scanner(System.in);
		System.out.println("Please enter a message to encrypt: ");
		if(!host.equals("")){
			plaintext = clientIn.nextLine();
		}

		socketSetup();
		byte[] hash = generateHash(plaintext);
		generateKeys();
		byte[] encryptedHash = encryptHash(hash);
		byte[] authMessage = authenticatePlaintext(encryptedHash, plaintext);
		byte[] compMessage = compressMessage(authMessage);
		generateSecretKey();
		byte[] ciphertext = generateCiphertext(compMessage);
		generateIV();
		getKUS();
		byte[] encryptedKey = encryptSecretKey();
		byte[] finCiphertext = generateFinalCiphertext(encryptedKey, ciphertext);
		sendMessage(finCiphertext);
	}

	/**
	*creating keys from stored bytes
	*/
	public void createStoredKeys(){
		//System.out.println("**************************called");
		try {
			//create server keys from stored bytes
			KUS = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(KUSA));
			KUC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(KUCA));
			KRC= KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(KRCA));
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	/**
	 * Open a socket on a given host and port. Open input and output streams
	 */
	public void socketSetup () {
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

		System.out.println("_.:CONNECTION TO SERVER ESTABLISHED AT "  + host + ":2222:._\n");
	}

	/*
	Generate Message digest
	*/
	/**
	 * Generates message digest (hash) of Plaintext
	 * @param String Plaintext	plaintext to be encrypted
	 * @return byte[] hash		hash of plaintext (using SHA-256)
	 */
	public byte[] generateHash (String plaintext) {
		System.out.println("_.:SETTING UP AUTHENTICATION:._");
		byte[] hash = null;
		byte[] signedPlaintext = null;
		try {
			//CREATE A HASH OF THE MESSAGE


			System.out.println("\n\t.:CREATING MESSAGE DIGEST:.");
			System.out.println("\t\tPlaintext: " + plaintext);
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(plaintext.getBytes("UTF-8"));
			hash = md.digest();
			int mdValue = 0;
			for (int i = 0; i < hash.length; i++){
				mdValue += hash[i];
			}

			System.out.println("\t\tMessage Digest Summation: " + mdValue);

			System.out.println("\t\tMessage Digest Size: " + hash.length);
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return hash;
	}

	/**
	 * Generate the public/private key pair for the client (KRC, KUC)
	 */
	public void generateKeys () {
		try {
			//create private and public keys for client
			System.out.println("\n\t.:CREATING PRIVATE AND PUBLIC KEY PAIR:.");
			/*KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keys = keyGen.generateKeyPair();

			//get the key from the generator
			KRC = keys.getPrivate();
			KUC = keys.getPublic();

			System.out.println("**********************");
			for (int i = 0; i < KRC.getEncoded().length;i++ ) {
				System.out.print(KRC.getEncoded()[i]+",");
			}
			System.out.println("**********************");
			for (int i = 0; i < KUC.getEncoded().length;i++ ) {
				System.out.print(KUC.getEncoded()[i]+",");
			}*/
			createStoredKeys();

			//convert to bytes
			byte[] KUCArray = KUC.getEncoded();

			//for printing
			int count1 = 0;
			for (int i = 0; i < KUCArray.length; i++){
				count1 += KUCArray[i];
			}
			System.out.println("\t\tPublic Key Summation: " + count1);

			/*System.out.println("\t\tWriting Public Key to file \"client_public_key.txt\"");
			//write out the public key to a file
			FileOutputStream fos = new FileOutputStream("client_public_key.txt");
			fos.write(KUCArray);
			fos.close();*/
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	/**
	 * Generates the digital signature by encrypting the hash with KRC (for authenticity)
	 * @param  byte[] hash 				hash of plaintext (using SHA-256)
	 * @return byte[] encryptedHash 	the digital signature (usign RSA, ECB with PKCS1Padding)
	 */
	public byte[] encryptHash (byte[] hash) {
		System.out.println("\n\t.:SIGNING HASH WITH CLIENTS PRIVATE KEY:.");

		System.out.println("\t\tEncrypting Hash with Private Key");
		//sign hash with private key
		byte[] encryptedHash = null;
		try {
			Cipher RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			RSAcipher.init(Cipher.ENCRYPT_MODE, KRC);
			encryptedHash = RSAcipher.doFinal(hash);

			int count2 = 0;
			for (int i = 0; i < encryptedHash.length; i++){
				count2 += encryptedHash[i];
			}

			System.out.println("\t\tEncrypted Hash Summation: " + count2);


		}
		catch (Exception e) {
			System.err.println(e);
		}
		return encryptedHash;
	}

	/**
	 * Concatentates the digital signature to the plaintext (for authentication)
	 * @param	byte[] encryptedHash	the digital signature (usign RSA, ECB with PKCS1Padding)
	 * @param	String plaintext		the plaintext to be Encrypted
	 * @return	byte[] authMessage		the concatentated payload to be encrypted for confidentiality
	 */
	public byte[] authenticatePlaintext (byte[] encryptedHash, String plaintext) {
		System.out.println("\n\t.:CONCATENATING SIGNATURE AND MESSAGE:.");
		byte[] authMessage = null;
		try {
			//concantenate hash and original message

			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			//add signature
			outputStream.write(encryptedHash);
			//add message
			outputStream.write(plaintext.getBytes("UTF-8"));
			//concat
			authMessage = outputStream.toByteArray();
			outputStream.close();

			int count3 = 0;
			for (int i = 0; i < authMessage.length; i++){
				count3 += authMessage[i];
			}
			System.out.println("\t\tAthenticated Packet Summation: " + count3);
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return authMessage;
	}

	/**
	 * Compresses the payload for encryption
	 * @param	byte[] authMessage	the payload to be encrypted (Digital Signature + Plaintext)
	 * @return	byte[] compMessage	the compressed payload to be encrypted
	 */
	public byte[] compressMessage (byte[] authMessage) {
		System.out.println("\n\t.:COMPRESSING AUTHENTICATED PACKET:.");
		byte[] compMessage = null;
		try {

			//zip the above

			//using chunks of 1024 bytes
			byte[] output = new byte[1024];
			//create defalter
			Deflater compress = new Deflater();
			compress.setInput(authMessage);
			//use byte array to avoid running out of space
			ByteArrayOutputStream o = new ByteArrayOutputStream(authMessage.length);
			compress.finish();

			//create zip
			while(!compress.finished()){
				int count = compress.deflate(output);
				o.write(output,0,count);
			}
			o.close();
			compress.end();

			//zipped message
			compMessage = o.toByteArray();

			int count4 = 0;
			for (int i = 0; i < compMessage.length; i++){
				count4 += compMessage[i];
			}
			System.out.println("\t\tCompressed Packet Summation: " + count4);

			System.out.println("\n_.:AUTHENTICATION COMPLETE:._");
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return compMessage;
	}

	/**
	 * Generates the secret/shared key Ks to be used by the server to decrypt the payload
	 */
	public void generateSecretKey () {
		try {
			System.out.println("\n\n_.:SETTING UP CONFIDENTIALITY:._");

			//create shared key
			System.out.println("\n\t.:CREATING SHARED KEY:.");
			KeyGenerator secretKeyGen = KeyGenerator.getInstance("AES");
	        secretKeyGen.init(128);
			//GET KEY
	        secretKey = secretKeyGen.generateKey();
			//new key spec
			k = new SecretKeySpec(secretKey.getEncoded(), "AES");

			int count5 = 0;
			for (int i = 0; i < secretKey.getEncoded().length; i++){
				count5 += secretKey.getEncoded()[i];
			}
			System.out.println("\t\tShared Key Summation: " + count5);
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	/**
	 * Encrypt the compressed payload
	 * @param	byte[] compMessage	the compressed payload to be encrypted
	 * @return	byte[] ciphertext	E_(Ks){Z(DS + P)}
	 */
	public byte[] generateCiphertext (byte[] compMessage) {
		System.out.println("\n\t.:ENCRYPTING COMPRESSED PACKET WITH SHARED KEY:.");
		//create cipher for encryption and encrypt zip\

		byte[] ciphertext = null;
		try {
			aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aescipher.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(ivSpecStored));
			ciphertext = aescipher.doFinal(compMessage);


			int count6 = 0;
			for (int i = 0; i < ciphertext.length; i++){
				count6 += ciphertext[i];
			}
			System.out.println("\t\tEncrypted Compressed Packet Summation: " + count6);
		}
		catch (Exception e) {
			System.err.println(e);
		}

		return ciphertext;
	}

	/**
	 * Generates the initiation vector for CBC mode encryption and stores it for server to use when decrypting the compressed payload (DS + P)
	 */
	public void generateIV () {
		try {
			System.out.println("\t\tGenerating IV for decryption");



			//get iv from cipher
			//byte[] iv = aescipher.getIV();

			int count7 = 0;
			for (int i = 0; i < ivSpecStored.length; i++){
				count7 += ivSpecStored[i];
				//System.out.print(iv[i]+",");
			}
			System.out.println("\t\tIV Summation: " + count7);
			//write iv to a file
			/*System.out.println("\t\tWriting IV to file \"client_iv.txt\"");
			FileOutputStream fos2 = new FileOutputStream("client_iv.txt");
			fos2.write(iv);
			fos2.close();*/
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	/**
	 * Acquire the server's public key KUS
	 */
	public void getKUS () {
		/*try {
			// get server key from file
			System.out.println("\t\tReading in public key from file \"server_public_key.txt\"");
			Path path = Paths.get("server_public_key.txt");
			byte[] SKey = Files.readAllBytes(path);

			//create server key from bytes
			KUS = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(SKey));
		}
		catch (Exception e) {
			System.err.println(e);
		}*/
	}

	/**
	 * Encrypts the shared/secret key Ks
	 * @return byte[] encryptedKey	E_(KUS){Ks}
	 */
	public byte[] encryptSecretKey () {
		System.out.println("\n\t.:ENCRYPTING SHARED KEY WITH SERVERS PUBLIC KEY:.");

		System.out.println("\t\tEncrypting shared key with Servers Public Key");
		//encrypt shared key with public key of server
		byte[] encryptedKey = null;
		try {
			Cipher packet = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			packet.init(Cipher.ENCRYPT_MODE, KUS);
			encryptedKey = packet.doFinal(secretKey.getEncoded());

			int count8 = 0;
			for (int i = 0; i < encryptedKey.length; i++){
				count8 += encryptedKey[i];
			}
			System.out.println("\t\tEncrypted Shared Key Summation: " + count8);
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return encryptedKey;
	}

	/**
	 *Concatenates the encrypted shared/secret key with the compressed and encrypted digital signature and plaintext
	 *@param  byte[] encryptedKey  E_(KUS){Ks}
	 *@param  byte[] ciphertext    encrypted + compressed payload E_(Ks){Z(DS + P)}
	 *@return byte[] finCiphertext the message to be sent to the server
	 */
	public byte[] generateFinalCiphertext (byte[] encryptedKey, byte[] ciphertext) {
		System.out.println("\n\t.:CONCATENATING ENCRYPTED SHARED KEY AND ENCRYPTED PACKAGE:.");
		byte[] finCiphertext = null;
		try {

			//concat the encrypyted shared key and the encrypted zip

			ByteArrayOutputStream finalMessage = new ByteArrayOutputStream( );
			finalMessage.write(encryptedKey);
			finalMessage.write(ciphertext);
			finCiphertext = finalMessage.toByteArray();
			finalMessage.close();

			int count9 = 0;
			for (int i = 0; i < finCiphertext.length; i++){
				count9 += finCiphertext[i];
			}
			System.out.println("\t\tEncrypted Packet Summation: " + count9);


			System.out.println("\n_.:CONFIDENTIALITY COMPLETE:._");
		}
		catch (Exception e) {
			System.err.println(e);
		}

		return finCiphertext;
	}

	/**
	 * Sends encrypted message to server.
	 * @param byte[] finCiphertext - encrypted message to send.
	 */
	public void sendMessage (byte[] finCiphertext) {
		try {
			System.out.println("\n\n_.:SENDING MESSAGE TO SERVER:._");
			//send off
			System.out.println("\t\tFinal Packet Size: " + finCiphertext.length);
			int count10 = 0;
			for (int i = 0; i < finCiphertext.length; i++){
				count10 += finCiphertext[i];
			}
			System.out.println("\t\tFinal Packet Summation: " + count10);


			os.writeInt(finCiphertext.length);
			os.write(finCiphertext);
			System.out.println("_.:MESSAGE SENT TO SERVER:._");

			//System.out.println("\n_.:CONNECTION TO SERVER CLOSED:._");
		}

		catch (Exception e) {
			System.err.println(e);
		}
	}

	public static void main (String[] args){
		Client client = new Client();
	}

}
