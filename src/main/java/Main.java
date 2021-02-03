import io.jsonwebtoken.Claims;
import jwt.TokenService;
import rsaEncodeDecode.EncDec;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static jwt.TokenService.generateKeyPair;

public class Main {
    private final static String ENCODED_TEXT = "";

    public static void main(String[] args) {
//        Main.encryptDecrypt("Hello World!");
        Main.jwsShowOff();
    }

    public static void jweShowOff() {

    }

    public static void jwsShowOff() {
        KeyPair keyPair = generateKeyPair();

        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        System.out.println("Public key: " + EncDec.keyToNumber(aPublic.getEncoded()).toString());
        System.out.println("Private key: " + EncDec.keyToNumber(aPrivate.getEncoded()).toString() + "\n");


        String jwt = TokenService.createJWT("Id", "Artsapollo", "Subject", 100000L, aPrivate);
        System.out.println("Created JWT: " + jwt + "\n");

        Claims claims = TokenService.confirmSignatureJWT(jwt, aPublic);
        System.out.println("Confirmed JWT Claims: " + claims);
    }

    public static void encryptDecrypt(String plainText) {
        EncDec encDec = new EncDec();

        System.out.println("PlainText: " + plainText);
        System.out.println("PlainText size: " + plainText.length() + "\n");

        System.out.println("Encryption key length: " + encDec.getMEncryptionKeyLength());
        System.out.println("Encryption algorithm: " + encDec.getMEncryptionAlgo());
        System.out.println("Encryption transform: " + encDec.getMTransformation() + "\n");

        byte[] encryptedText = encDec.encryptText(plainText);
        System.out.println("Encrypted text: " + EncDec.keyToNumber(encryptedText).toString());
        System.out.println("Encrypted text length: " + EncDec.keyToNumber(encryptedText).toString().length() + "\n");

        System.out.println("Public key: " + EncDec.keyToNumber(encDec.getPrivateKeyAsByteArray()).toString());
        System.out.println("Public key length: " + EncDec.keyToNumber(encDec.getPrivateKeyAsByteArray()).toString().length());
        System.out.println("Private key: " + EncDec.keyToNumber(encDec.getPublicKeyAsByteArray()).toString());
        System.out.println("Private key length: " + EncDec.keyToNumber(encDec.getPublicKeyAsByteArray()).toString().length() + "\n");

        String decryptedText = new String(encDec.decryptText(encryptedText));
        System.out.println("Decrypted text: " + decryptedText);
        System.out.println("Decrypted text length: " + decryptedText.length());
    }
}
