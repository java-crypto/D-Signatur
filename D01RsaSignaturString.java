package net.bplaced.javacrypto.signature;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 09.01.2019 
* Funktion: signiert und verifiziert einen Text mittels RSA (Asymmetrisch)
* Function: signs and verifies a text string using RSA (asymmetric)
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import javax.xml.bind.DatatypeConverter;

public class D01RsaSignaturString {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
		System.out.println("D01 RSA Signatur mit einem String");
		// KeyPair generieren
		// Hinweis: RSA-Unterschriften werden ab einer Schlüssellänge von 2.048 Bit als
		// sicher angesehen. Hier wird die Länge von 512 Bit nur verwendet, um die
		// Ausgabe der erzeugten Schlüssel "klein" zu halten
		int rsaKeyLengthInt = 512; // 512, 1024, 2048, 4096, 9192 bit
		String rsaHashverfahrenString = "SHA256withRSA"; // SHA256withRSA, SHA384withRSA, SHA512withRSA
		KeyPair keyPair = generateRsaKeyPair(rsaKeyLengthInt);
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		// ausgabe der schlüsseldaten
		System.out.println("\nprivateKey  Länge:" + privateKey.getEncoded().length + " Data:\n"
				+ byteArrayPrint(privateKey.getEncoded(), 33));
		System.out.println("\npublicKey   Länge: " + publicKey.getEncoded().length + " Data:\n"
				+ byteArrayPrint(publicKey.getEncoded(), 33));
		System.out.println("\nPublic Key : " + publicKey.toString());
		// diese nachricht soll signiert werden
		String messageString = "Nachricht fuer Signatur";
		byte[] messageByte = messageString.getBytes("utf-8");
		System.out.println("\nOriginal-Nachricht         :" + messageString);
		System.out.println("Original-Nachricht hex     :" + DatatypeConverter.printHexBinary(messageByte));
		// die signatur erfolgt mit dem privaten schlüssel
		byte[] signatureByte = signRsa(privateKey, rsaHashverfahrenString, messageByte);
		System.out.println(
				"\nsignatureByte Länge:" + signatureByte.length + " Data:\n" + byteArrayPrint(signatureByte, 33));
		// die überprüfung der signatur erfolgt mit dem öffentlichen schlüssel
		System.out.println("\nÜberprüfung der Signatur");
		boolean signatureIsCorrectBoolean = verifyRsa(publicKey, rsaHashverfahrenString, messageByte, signatureByte);
		System.out.println("Signatur ist korrekt       :" + signatureIsCorrectBoolean);
		// veränderung der nachricht
		System.out.println("\nVeränderung der Nachricht");
		messageByte = "Nachricht fuer Signatur2".getBytes("utf-8");
		System.out.println("Veränderte-Nachricht hex   :" + DatatypeConverter.printHexBinary(messageByte));
		signatureIsCorrectBoolean = verifyRsa(publicKey, rsaHashverfahrenString, messageByte, signatureByte);
		System.out.println("Signatur ist korrekt       :" + signatureIsCorrectBoolean);
	}
	public static KeyPair generateRsaKeyPair(int keylengthInt) throws NoSuchAlgorithmException {
		KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
		keypairGenerator.initialize(keylengthInt, new SecureRandom()); // Achtung: die keylänge von 512 bit ist unsicher
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
	public static String byteArrayPrint(byte[] byteData, int numberPerRow) {
		String returnString = "";
		String rawString = DatatypeConverter.printHexBinary(byteData);
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
}
