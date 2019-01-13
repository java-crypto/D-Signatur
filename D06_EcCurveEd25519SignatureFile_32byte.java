package net.bplaced.javacrypto.signature;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 13.01.2019 
* Funktion: signiert und verifiziert eine Datei mittels EC Kurve ED25519 (Asymmetrisch)
* Function: signs and verifies a file using EC curve ED25519 (asymmetric)
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

/*
* Wichtiger Hinweis / important notice
* Du benötigst eine externe Jar-Bibliothek namens eddsa-0.3.0.jar
* You need an external jar-library eddsa-0.3.0.jar
* Die Bibliothek ist hier downloadbar / the library can get obtained here:
* http://central.maven.org/maven2/net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar
* Die Nutzung der Bibliothek steht unter dieser Lizenz:
* Please keep in mind that this library is available under this licence:
* Creative Commons Legal Code CC0 1.0 Universal
*/

//diese version erzeugt 32-byte lange private und public keys
//die damit mit bc vergleichbar und austauschbar sind
//ebenso werden 32 byte keys eingelesen und in eddsa keys zurück gewandelt
//zusätzlich kann das programm aus einem privateKey wieder einen public key erzeugen
//diese version kann die 32-byte keys speichern und einlesen

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class D06_EcCurveEd25519SignatureFile_32byte {

	public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException,
			InvalidKeyException, SignatureException, IOException, NoSuchProviderException {
		System.out.println("D06 EC Kurve ED25519 (Bibliothek eddsa-0.3.0.jar) Signatur mit einer Datei");

		String messageFilenameString = "d02_message.txt";
		// KeyPair generieren
		KeyPair keyPair = generateEcEd25519KeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		String ecEd25519PrivateKeyFilenameString = "ec_privateKey_" + "ED25519" + "_32byte.privatekey";
		String ecEd25519PublicKeyFilenameString = "ec_publicKey_" + "ED25519" + "_32byte.publickey";
		String ecEd25519SignatureFilenameString = "ec_ed25519_Signature.dat";
		// ausgabe der schlüsseldaten
		System.out.println("\nprivate Key  Länge:" + privateKey.getEncoded().length + " Data:\n"
				+ byteArrayPrint(privateKey.getEncoded(), 33));
		System.out.println("\npublic Key   Länge: " + publicKey.getEncoded().length + " Data:\n"
				+ byteArrayPrint(publicKey.getEncoded(), 33));
		System.out.println("\nPublic Key: " + publicKey.toString());
		// speicherung der beiden keys
		saveEd25519_32byte_PrivateKeyAsBytearray(privateKey, ecEd25519PrivateKeyFilenameString);
		saveEd25519_32byte_PublicKeyAsBytearray(publicKey, ecEd25519PublicKeyFilenameString);
		System.out.println("Der privateKey und publicKey wurden gespeichert:" + ecEd25519PrivateKeyFilenameString + "/"
				+ ecEd25519PublicKeyFilenameString);
		// diese nachricht soll signiert werden
		// hier wird der hashwert der datei signiert um die datenmenge innerhalb der
		// signatur gering zu halten:
		byte[] messageByte = calcSHA256BufferedFile(messageFilenameString);
		System.out.println("\nDie Datei wurde gelesen:" + messageFilenameString + " und der SHA256-Hashwert erzeugt:"
				+ printHexBinary(messageByte));
		// die signatur erfolgt mit dem privaten schlüssel, der jetzt geladen wird
		PrivateKey privateKeyLoad = loadEcEd25519_32byte_PrivateKeyAsBytearray(ecEd25519PrivateKeyFilenameString);
		System.out.println("\nDer privateKey wurde zur Signatur geladen:\"" + ecEd25519PrivateKeyFilenameString);
		byte[] signatureByte = signEcEd25519PrivateKey(privateKeyLoad, messageByte);
		System.out.println(
				"\nsignatureByte Länge:" + signatureByte.length + " Data:\n" + byteArrayPrint(signatureByte, 33));
		// speicherung der signatur
		writeBytesToFileNio(signatureByte, ecEd25519SignatureFilenameString);
		System.out.println("Die ecSignatur wurde gespeichert:" + ecEd25519SignatureFilenameString);
		// die überprüfung der signatur erfolgt mit dem öffentlichen schlüssel, der
		// jetzt geladen wird
		PublicKey publicKeyLoad = loadEcEd25519_32byte_PublicKeyAsBytearray(ecEd25519PublicKeyFilenameString);
		System.out.println("\nDer publicKey wurde zur Verifizierung geladen:" + ecEd25519PublicKeyFilenameString);
		byte[] messageLoadByte = calcSHA256BufferedFile(messageFilenameString);
		System.out.println("Die message wurde gelesen:" + messageFilenameString + " und der SHA256-Hashwert erzeugt:"
				+ printHexBinary(messageLoadByte));
		byte[] signatureLoadByte = readBytesFromFileNio(ecEd25519SignatureFilenameString);
		System.out.println("Die Signature wurde gelesen:" + ecEd25519SignatureFilenameString);
		boolean signatureIsCorrectBoolean = verifyEcEd25519PublicKey(publicKeyLoad, messageLoadByte, signatureLoadByte);
		System.out.println(
				"\nÜberprüfung der Signatur mit dem publicKey: die Signatur ist korrekt:" + signatureIsCorrectBoolean);
		// veränderung der nachricht
		System.out.println("\nVeränderung der Nachricht");
		messageByte = "Nachricht fuer Signatur2".getBytes("utf-8");
		System.out.println("Veränderte-Nachricht hex   :" + byteArrayPrint(messageByte, 33));
		signatureIsCorrectBoolean = verifyEcEd25519PublicKey(publicKeyLoad, messageByte, signatureLoadByte);
		System.out.println(
				"\nÜberprüfung der Signatur mit dem publicKey: die Signatur ist korrekt:" + signatureIsCorrectBoolean);
	}

	public static KeyPair generateEcEd25519KeyPair() {
		SecureRandom secureRandom = new SecureRandom();
		KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
		keyPairGenerator.initialize(256, secureRandom);
		return keyPairGenerator.generateKeyPair();
	}

	public static byte[] signEcEd25519PrivateKey(PrivateKey privateKey, byte[] messageByte)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
		Signature signature = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
		signature.initSign(privateKey);
		signature.update(messageByte);
		return signature.sign();
	}

	public static Boolean verifyEcEd25519PublicKey(PublicKey publicKey, byte[] messageByte, byte[] signatureByte)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
		Signature signature = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
		signature.initVerify(publicKey);
		signature.update(messageByte);
		return signature.verify(signatureByte);
	}

	private static void saveEd25519_32byte_PrivateKeyAsBytearray(PrivateKey key, String filenameString) throws IOException, InvalidKeySpecException {
		PKCS8EncodedKeySpec priEncoded = new PKCS8EncodedKeySpec(key.getEncoded());
		EdDSAPrivateKey eddsaPrivateKey = new EdDSAPrivateKey(priEncoded);
		byte[] priSeedByte = eddsaPrivateKey.getSeed();
		FileOutputStream fos = new FileOutputStream(filenameString);
		fos.write(priSeedByte);
		fos.close();
	}
	
	private static void saveEd25519_32byte_PublicKeyAsBytearray(PublicKey key, String filenameString) throws IOException, InvalidKeySpecException {
		X509EncodedKeySpec pubEncoded = new X509EncodedKeySpec(key.getEncoded());
		EdDSAPublicKey eddsaPublicKey = new EdDSAPublicKey(pubEncoded);
		byte[] pubSeedByte = eddsaPublicKey.getA().toByteArray();
		FileOutputStream fos = new FileOutputStream(filenameString);
		fos.write(pubSeedByte);
		fos.close();
	}

	private static PrivateKey loadEcEd25519_32byte_PrivateKeyAsBytearray(String filenameString)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		File filenameKeyString = new File(filenameString);
		FileInputStream fis = new FileInputStream(filenameKeyString);
		byte[] encodedPrivateKey = new byte[(int) filenameKeyString.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		EdDSAParameterSpec ed25519Spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
		EdDSAPrivateKeySpec privateKeyRebuildSpec = new EdDSAPrivateKeySpec(encodedPrivateKey, ed25519Spec);
		return new EdDSAPrivateKey(privateKeyRebuildSpec);
	}

	private static PublicKey loadEcEd25519_32byte_PublicKeyAsBytearray(String filenameString)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		File filenameKeyString = new File(filenameString);
		FileInputStream fis = new FileInputStream(filenameKeyString);
		byte[] encodedPublicKey = new byte[(int) filenameKeyString.length()];
		fis.read(encodedPublicKey);
		fis.close();
		EdDSAParameterSpec ed25519Spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
		EdDSAPublicKeySpec publicKeyRebuildSpec = new EdDSAPublicKeySpec(encodedPublicKey, ed25519Spec);
		return new EdDSAPublicKey(publicKeyRebuildSpec);
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
		// liest die datei über einen buffer ein - sehr viel geringere speichernutzung
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
