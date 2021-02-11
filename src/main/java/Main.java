import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import io.jsonwebtoken.Claims;
import jjwt.TokenWorkaround;
import jwt.TokenService;
import rsaEncodeDecode.EncDec;
import util.KeyUtils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static util.KeyUtils.Y_ENCODED_TEXT;
import static util.KeyUtils.xCertificatePublicKeyExtractor;


public class Main {


    public static void main(String[] args) {
//        Main.encryptDecrypt("Hello World!");
//        Main.jwsShowOff();
//        TokenService.createFullJwt();
//        Main.generateKeys("123", KeyUse.SIGNATURE);
//        Main.visaTestDecryption(KeyUtils.PUBLIC_KEY, KeyUtils.PRIVATE_KEY, ENCODED_TEXT);

        EncryptedJWT encryptedJWT = TokenService.decryptInputJwe(Y_ENCODED_TEXT, KeyUtils.Y_PRIVATE_KEY);
        boolean signatureValid = TokenService.isSignatureValid(encryptedJWT.serialize(), KeyUtils.Y_PUBLIC_KEY);
        System.out.println(signatureValid);

    }

    public static void visaTestDecryption(String cert, String prvt, String encryptedJwt) {
        RSAKey rsaPublicKey = xCertificatePublicKeyExtractor(cert);
        System.out.println("Converted RSA public key: " + rsaPublicKey);
        RSAKey rsaPrivateKey = xCertificatePublicKeyExtractor(cert);
        System.out.println("Converted RSA private key: " + rsaPrivateKey);

        System.out.println("Input JWT: " + encryptedJwt);


//        JWEDecrypter decrypter = new RSADecrypter(rsaPrivateKey);


//        //Decrypt
        TokenService.readJwt(encryptedJwt, null, rsaPublicKey);

    }


    public static void jwsShowOff() {
        KeyPair keyPair = KeyUtils.generateKeyPair();

        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        System.out.println("Public key: " + EncDec.keyToNumber(aPublic.getEncoded()).toString());
        System.out.println("Private key: " + EncDec.keyToNumber(aPrivate.getEncoded()).toString() + "\n");


        String jwt = TokenWorkaround.createJWT("Id", "Artsapollo", "Subject", 100000L, aPrivate);
        System.out.println("Created JWT: " + jwt + "\n");

        Claims claims = TokenWorkaround.confirmSignatureJWT(jwt, aPublic);
        System.out.println("Confirmed JWT Claims: " + claims);
    }


    public static void rsaEncryptDecrypt(String plainText) {
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
