package net.bplaced.javacrypto.signature;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 18.01.2019 
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
* Du benötigst eine externe Jar-Bibliothek namens bcprov-jdk15on-161b20.jar (version 1.605)
* You need an external jar-library bcprov-jdk15on-161b20.jar (version 1.605)
* Das Programm nutzt eine BouncyCastle Beta-Version, daher sind höhere Versionsnummern vermutlich ebenfalls nutzbar
* The programm works with BouncyCastle beta versions so higher version numbers will probably work as well
* Die Bibliothek ist hier downloadbar / the library can get obtained here:
* https://downloads.bouncycastle.org/betas/
*/

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class D07_EcCurve25519BcBetaSignatureFile {

	public static void main(String[] args)
			throws DataLengthException, CryptoException, IOException, NoSuchAlgorithmException, InvalidKeyException,
			SignatureException, InvalidKeySpecException, NoSuchProviderException {
		System.out.println("D07 EC Kurve ED25519 BC Signatur mit einer Datei");

		// benötigt die neueste jar-datei von bc
		Security.addProvider(new BouncyCastleProvider());
		Provider provider = Security.getProvider("BC");
		System.out.println("Provider          :" + provider.getName() + " Version: " + provider.getVersion());

		String messageFilenameString = "d02_message.txt";
		// KeyPair generieren
		AsymmetricCipherKeyPair keyPair = generateEcEd25519BcKeyPair();
		Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
		Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();
		String ecEd25519BcPrivateKeyFilenameString = "ec_privateKey_" + "ED25519_BC" + ".privatekey";
		String ecEd25519BcPublicKeyFilenameString = "ec_publicKey_" + "ED25519_BC" + ".publickey";
		String ecEd25519BcSignatureFilenameString = "eced25519_BC__Signature.dat";
		// ausgabe der schlüsseldaten
		System.out.println("\nprivate Key  Länge:" + privateKey.getEncoded().length + " Data:\n"
				+ byteArrayPrint(privateKey.getEncoded(), 33));
		System.out.println("\npublic Key   Länge: " + publicKey.getEncoded().length + " Data:\n"
				+ byteArrayPrint(publicKey.getEncoded(), 33));
		System.out.println("\nPublic Key: " + publicKey.toString());
		// speicherung der beiden keys

		savePrivateEd25519BcKeyAsBytearray(privateKey, ecEd25519BcPrivateKeyFilenameString);
		savePublicEd25519BcKeyAsBytearray(publicKey, ecEd25519BcPublicKeyFilenameString);
		System.out.println("Der privateKey und publicKey wurden gespeichert:" + ecEd25519BcPrivateKeyFilenameString
				+ "/" + ecEd25519BcPublicKeyFilenameString);

		// diese nachricht soll signiert werden
		// hier wird der hashwert der datei signiert um die datenmenge innerhalb der
		// signatur gering zu halten:
		byte[] messageByte = calcSHA256BufferedFile(messageFilenameString);
		System.out.println("\nDie Datei wurde gelesen:" + messageFilenameString + " und der SHA256-Hashwert erzeugt:"
				+ printHexBinary(messageByte));

		// die signatur erfolgt mit dem privaten schlüssel, der jetzt geladen wird
		Ed25519PrivateKeyParameters privateKeyLoad = loadEcEd25519BcPrivateKeyAsBytearray(
				ecEd25519BcPrivateKeyFilenameString);
		System.out.println("\nDer privateKey wurde zur Signatur geladen:\"" + ecEd25519BcPrivateKeyFilenameString);
		byte[] signatureByte = signEcEd25519BcPrivateKey(privateKeyLoad, messageByte);
		System.out.println(
				"\nsignatureByte Länge:" + signatureByte.length + " Data:\n" + byteArrayPrint(signatureByte, 33));
		// speicherung der signatur
		writeBytesToFileNio(signatureByte, ecEd25519BcSignatureFilenameString);
		System.out.println("Die ecSignatur wurde gespeichert:" + ecEd25519BcSignatureFilenameString);

		// die überprüfung der signatur erfolgt mit dem öffentlichen schlüssel, der
		// jetzt geladen wird
		Ed25519PublicKeyParameters publicKeyLoad = loadEcEd25519BcPublicKeyAsBytearray(ecEd25519BcPublicKeyFilenameString);
		System.out.println("\nDer publicKey wurde zur Verifizierung geladen:" + ecEd25519BcPublicKeyFilenameString);
		byte[] messageLoadByte = calcSHA256BufferedFile(messageFilenameString);
		System.out.println("Die message wurde gelesen:" + messageFilenameString + " und der SHA256-Hashwert erzeugt:"
				+ printHexBinary(messageLoadByte));
		byte[] signatureLoadByte = readBytesFromFileNio(ecEd25519BcSignatureFilenameString);
		System.out.println("Die Signature wurde gelesen:" + ecEd25519BcSignatureFilenameString);

		boolean signatureIsCorrectBoolean = verifyEcEd25519BcPublicKey(publicKeyLoad, messageLoadByte, signatureLoadByte);
		System.out.println(
				"\nÜberprüfung der Signatur mit dem publicKey: die Signatur ist korrekt:" + signatureIsCorrectBoolean);
		
		// veränderung der nachricht
		System.out.println("\nVeränderung der Nachricht");
		messageByte = "Nachricht fuer Signatur2".getBytes("utf-8");
		System.out.println("Veränderte-Nachricht hex   :" + byteArrayPrint(messageByte, 33));
		signatureIsCorrectBoolean = verifyEcEd25519BcPublicKey(publicKeyLoad, messageByte, signatureLoadByte);
		System.out.println(
				"\nÜberprüfung der Signatur mit dem publicKey: die Signatur ist korrekt:" + signatureIsCorrectBoolean);
	}

	public static AsymmetricCipherKeyPair generateEcEd25519BcKeyPair() {
		SecureRandom RANDOM = new SecureRandom();
		Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
		keyPairGenerator.init(new Ed25519KeyGenerationParameters(RANDOM));
		return keyPairGenerator.generateKeyPair();
	}

	public static byte[] signEcEd25519BcPrivateKey(Ed25519PrivateKeyParameters privateKey, byte[] messageByte)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, DataLengthException,
			CryptoException {
		Signer signer = new Ed25519Signer();
		signer.init(true, privateKey);
		signer.update(messageByte, 0, messageByte.length);
		return signer.generateSignature();
	}

	public static Boolean verifyEcEd25519BcPublicKey(Ed25519PublicKeyParameters publicKey, byte[] messageByte,
			byte[] signatureByte) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Signer verifier = new Ed25519Signer();
		verifier.init(false, publicKey);
		verifier.update(messageByte, 0, messageByte.length);
		return verifier.verifySignature(signatureByte);
	}

	private static void savePrivateEd25519BcKeyAsBytearray(Ed25519PrivateKeyParameters privateKey,
			String filenameString) throws IOException {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(filenameString);
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}

	private static void savePublicEd25519BcKeyAsBytearray(Ed25519PublicKeyParameters publicKey, String filenameString)
			throws IOException {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(filenameString);
		fos.write((x509EncodedKeySpec).getEncoded());
		fos.close();
	}

	private static Ed25519PrivateKeyParameters loadEcEd25519BcPrivateKeyAsBytearray(String filenameString)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		File filenameKeyString = new File(filenameString);
		FileInputStream fis = new FileInputStream(filenameKeyString);
		byte[] encodedPrivateKey = new byte[(int) filenameKeyString.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		return new Ed25519PrivateKeyParameters(encodedPrivateKey, 0);
	}

	private static Ed25519PublicKeyParameters loadEcEd25519BcPublicKeyAsBytearray(String filenameString)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		File filenameKeyString = new File(filenameString);
		FileInputStream fis = new FileInputStream(filenameKeyString);
		byte[] encodedPublicKey = new byte[(int) filenameKeyString.length()];
		fis.read(encodedPublicKey);
		fis.close();
		return new Ed25519PublicKeyParameters(encodedPublicKey, 0);
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
