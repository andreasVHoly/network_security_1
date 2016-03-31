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
	private PrivateKey KRC;
	private PublicKey KUC;
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

	/*Constructor that sets up chat connecting to a specific server.
	@params: IP address=> String serverIP
				   host=> host*/
	public Client (String serverIP, String host) {
		// The default port.
		portNumber = 2222;
		// The default host.
		host = host;

		//adding bouncy castle provider
		Security.addProvider(new BouncyCastleProvider());
		//default message
		String plaintext = "This is what we want to encrypt!!!!!!!! This is a message we are testing";


		//get input from the user to get a message to decrypt
		clientIn = new Scanner(System.in);
		System.out.println("Please enter a message to encrypt: ");
		if(!host.equals("")){
			plaintext = clientIn.nextLine();
		}
	}

	/*
	* Open a socket on a given host and port. Open input and output streams .
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

	public void generateKeys () {
		try {
			//create private and public keys for client
			System.out.println("\n\t.:CREATING PRIVATE AND PUBLIC KEY PAIR:.");
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keys = keyGen.generateKeyPair();

			//get the key from the generator
			KRC = keys.getPrivate();
			KUC = keys.getPublic();

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
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

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

	public byte[] generateCiphertext (byte[] compMessage) {
		System.out.println("\n\t.:ENCRYPTING COMPRESSED PACKET WITH SHARED KEY:.");
		//create cipher for encryption and encrypt zip\

		byte[] ciphertext = null;
		try {
			aescipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aescipher.init(Cipher.ENCRYPT_MODE, k);
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

	public void generateIV () {
		try {
			System.out.println("\t\tExtracting the IV for decryption");

			//get iv from cipher
			byte[] iv = aescipher.getIV();

			int count7 = 0;
			for (int i = 0; i < iv.length; i++){
				count7 += iv[i];
			}
			System.out.println("\t\tIV summation: " + count7);
			//write iv to a file
			System.out.println("\t\tWriting IV to file \"client_iv.txt\"");
			FileOutputStream fos2 = new FileOutputStream("client_iv.txt");
			fos2.write(iv);
			fos2.close();
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

	public void getKUS () {
		try {
			// get server key from file
			System.out.println("\t\tReading in public key from file \"server_public_key.txt\"");
			Path path = Paths.get("server_public_key.txt");
			byte[] SKey = Files.readAllBytes(path);

			//create server key from bytes
			KUS = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(SKey));
		}
		catch (Exception e) {
			System.err.println(e);
		}
	}

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
			System.out.println("\t\tEncrypted Shared Key summation: " + count8);
		}
		catch (Exception e) {
			System.err.println(e);
		}
		return encryptedKey;
	}

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
			System.out.println("\t\tEncrypted Packet summation: " + count9);


			System.out.println("\n_.:CONFIDENTIALITY COMPLETE:._");
		}
		catch (Exception e) {
			System.err.println(e);
		}

		return finCiphertext;
	}

	public void sendMessage (byte[] finCiphertext) {
		try {
			System.out.println("\n\n_.:SENDING MESSAGE TO SERVER:._");
			//send off
			System.out.println("\t\tFinal Packet Size: " + finCiphertext.length);
			int count10 = 0;
			for (int i = 0; i < finCiphertext.length; i++){
				count10 += finCiphertext[i];
			}
			System.out.println("\t\tFinal Packet summation: " + count10);


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
