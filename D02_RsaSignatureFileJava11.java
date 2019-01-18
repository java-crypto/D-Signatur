package net.bplaced.javacrypto.signature;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 13.01.2019
* Funktion: signiert und verifiziert eine Datei mittels RSA (Asymmetrisch)
* Function: signs and verifies a file using RSA (asymmetric)
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Pr�fen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class D02_RsaSignatureFileJava11 {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
			IOException, InvalidKeySpecException {
		System.out.println("D02 RSA Signatur einer Datei mit Buffered Read der messageByte-Datei");

		String messageFilenameString = "d02_message.txt";
		// KeyPair generieren
		// Hinweis: RSA-Unterschriften werden ab einer Schl�ssell�nge von 2.048 Bit als
		// sicher angesehen. Hier wird die L�nge von 512 Bit nur verwendet, um die
		// Ausgabe der erzeugten Schl�ssel "klein" zu halten
		int rsaKeyLengthInt = 512; // 512, 1024, 2048, 4096, 9192 bit
		String rsaHashverfahrenString = "SHA256withRSA"; // SHA256withRSA, SHA384withRSA, SHA512withRSA
		String rsaPrivateKeyFilenameString = "rsa_privateKey_" + rsaKeyLengthInt + ".privatekey";
		String rsaPublicKeyFilenameString = "rsa_publicKey_" + rsaKeyLengthInt + ".publickey";
		String rsaSignatureFilenameString = "rsa_Signature.dat";
		KeyPair keyPair = generateRsaKeyPair(rsaKeyLengthInt);
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		// ausgabe der schl�sseldaten
		System.out.println("\nprivate Key  L�nge:" + privateKey.getEncoded().length + " Data:\n"
				+ byteArrayPrint(privateKey.getEncoded(), 33));
		System.out.println("\npublic Key   L�nge: " + publicKey.getEncoded().length + " Data:\n"
				+ byteArrayPrint(publicKey.getEncoded(), 33));
		System.out.println("\nPublic Key: " + publicKey.toString());
		// speicherung der beiden keys
		savePrivateKeyAsBytearray(privateKey, rsaPrivateKeyFilenameString);
		savePublicKeyAsBytearray(publicKey, rsaPublicKeyFilenameString);
		System.out.println("\nDer privateKey und publicKey wurden gespeichert:" + rsaPrivateKeyFilenameString + "/"
				+ rsaPublicKeyFilenameString);
		// diese nachricht soll signiert werden
		// hier wird der hashwert der datei signiert um die datenmenge innerhalb der signatur gering zu halten:
		byte[] messageByte = calcSHA256BufferedFile(messageFilenameString);
		System.out.println("\nDie Datei wurde gelesen:" + messageFilenameString + " und der SHA256-Hashwert erzeugt:" + printHexBinary(messageByte));
		// die signatur erfolgt mit dem privaten schl�ssel, der jetzt geladen wird
		PrivateKey privateKeyLoad = loadRsaPrivateKeyAsBytearray(rsaPrivateKeyFilenameString);
		System.out.println("\nDer privateKey wurde zur Signatur geladen:" + rsaPrivateKeyFilenameString);
		byte[] signatureByte = signRsa(privateKeyLoad, rsaHashverfahrenString, messageByte);
		System.out.println(
				"\nsignatureByte L�nge:" + signatureByte.length + " Data:\n" + byteArrayPrint(signatureByte, 33));
		// speicherung der signatur
		writeBytesToFileNio(signatureByte, rsaSignatureFilenameString);
		System.out.println("Die rsaSignatur wurde gespeichert:" + rsaSignatureFilenameString);
		// die �berpr�fung der signatur erfolgt mit dem �ffentlichen schl�ssel, der
		// jetzt geladen wird
		PublicKey publicKeyLoad = loadRsaPublicKeyAsBytearray(rsaPublicKeyFilenameString);
		System.out.println("\nDer publicKey wurde zur Verifizierung geladen:" + rsaPublicKeyFilenameString);
		// byte[] messageLoadByte = readBytesFromFileNio(messageFilenameString);
		// hier nur den gehashten wert einlesen
		byte[] messageLoadByte = calcSHA256BufferedFile(messageFilenameString);
		System.out.println("Die message wurde gelesen:" + messageFilenameString + " und der SHA256-Hashwert erzeugt:" + printHexBinary(messageLoadByte));
		// signatur einlesen
		byte[] signatureLoadByte = readBytesFromFileNio(rsaSignatureFilenameString);
		System.out.println("Die Signature wurde gelesen:" + rsaSignatureFilenameString);
		// signatur �berpr�fen
		boolean signatureIsCorrectBoolean = verifyRsa(publicKeyLoad, rsaHashverfahrenString, messageLoadByte,
				signatureLoadByte);
		System.out.println("\n�berpr�fung der Signatur mit dem publicKey: die Signatur ist korrekt:" + signatureIsCorrectBoolean);
		// ver�nderung der nachricht
		System.out.println("\nVer�nderung der Nachricht");
		messageByte = "Nachricht fuer Signatur2".getBytes("utf-8");
		System.out.println("Ver�nderte-Nachricht hex   :" + byteArrayPrint(messageByte, 33));
		signatureIsCorrectBoolean = verifyRsa(publicKeyLoad, rsaHashverfahrenString, messageByte, signatureByte);
		System.out.println("�berpr�fung der Signatur mit dem publicKey: die Signatur ist korrekt:" + signatureIsCorrectBoolean);
	}
	public static KeyPair generateRsaKeyPair(int keylengthInt) throws NoSuchAlgorithmException {
		KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
		keypairGenerator.initialize(keylengthInt, new SecureRandom()); // Achtung: die keyl�nge von 512 bit ist unsicher
		return keypairGenerator.generateKeyPair();
	}
	public static byte[] signRsa(PrivateKey privateKey, String rsaInstanceString, byte[] messageByte)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Signature signature = Signature.getInstance(rsaInstanceString);
		signature.initSign(privateKey);
		signature.update(messageByte);
		return signature.sign();
	}
	public static Boolean verifyRsa(PublicKey publicKey, String rsaInstanceString, byte[] messageByte,
			byte[] signatureByte) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Signature publicSignature = Signature.getInstance(rsaInstanceString);
		publicSignature.initVerify(publicKey);
		publicSignature.update(messageByte);
		return publicSignature.verify(signatureByte);
	}
	private static void savePrivateKeyAsBytearray(PrivateKey key, String filenameString) throws IOException {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key.getEncoded());
		FileOutputStream fos = new FileOutputStream(filenameString);
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
	private static PrivateKey loadRsaPrivateKeyAsBytearray(String filenameString)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File filenameKeyString = new File(filenameString);
		FileInputStream fis = new FileInputStream(filenameKeyString);
		byte[] encodedPrivateKey = new byte[(int) filenameKeyString.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKeyRead = keyFactory.generatePrivate(privateKeySpec);
		return privateKeyRead;
	}
	private static void savePublicKeyAsBytearray(PublicKey key, String filenameString) throws IOException {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key.getEncoded());
		FileOutputStream fos = new FileOutputStream(filenameString);
		fos.write((x509EncodedKeySpec).getEncoded());
		fos.close();
	}
	private static PublicKey loadRsaPublicKeyAsBytearray(String filenameString)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File filenameKeyString = new File(filenameString);
		FileInputStream fis = new FileInputStream(filenameKeyString);
		byte[] encodedPublicKey = new byte[(int) filenameKeyString.length()];
		fis.read(encodedPublicKey);
		fis.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey publicKeyRead = keyFactory.generatePublic(publicKeySpec);
		return publicKeyRead;
	}
	private static byte[] readBytesFromFileNio(String filenameString) {
		byte[] byteFromFileByte = null;
		try {
			byteFromFileByte = Files.readAllBytes(Paths.get(filenameString));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return byteFromFileByte;
	}
	public static byte[] calcSHA256BufferedFile(String filenameString) throws IOException, NoSuchAlgorithmException {
		// liest die datei �ber einen buffer ein - sehr viel geringere speichernutzung
		byte[] buffer = new byte[8192];
		int count;
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(filenameString));
		while ((count = bis.read(buffer)) > 0) {
			digest.update(buffer, 0, count);
		}
		bis.close();

		byte[] hash = digest.digest();
		return hash;
	}
	private static void writeBytesToFileNio(byte[] byteToFileByte, String filenameString) {
		try {
			Path path = Paths.get(filenameString);
			Files.write(path, byteToFileByte);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public static String byteArrayPrint(byte[] byteData, int numberPerRow) {
		String returnString = "";
		String rawString = printHexBinary(byteData);
		int rawLength = rawString.length();
		int i = 0;
		int j = 1;
		int z = 0;
		for (i = 0; i < rawLength; i++) {
			z++;
			returnString = returnString + rawString.charAt(i);
			if (j == 2) {
				returnString = returnString + " ";
				j = 0;
			}
			j++;
			if (z == (numberPerRow * 2)) {
				returnString = returnString + "\n";
				z = 0;
			}
		}
		return returnString;
	}
	public static String printHexBinary(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}
