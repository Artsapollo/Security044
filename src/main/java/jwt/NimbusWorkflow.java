package jwt;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import util.KeyUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class NimbusWorkflow {
    public static void main(String[] args) {
        try {
            //Extract private key from string - Done
            String privateKeyContent = KeyUtils.PRIVATE_KEY.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

            KeyFactory kf = KeyFactory.getInstance("RSA");

            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);

            //Extract public key from cert - Done
            RSAPublicKey pubKey = xCertificatePublicKeyExtractor(KeyUtils.PUBLIC_KEY).toRSAPublicKey();


            System.out.println(privKey + "\n");
            System.out.println(pubKey);

            boolean signatureValid = NimbusWorkflow.isSignatureValid(KeyUtils.ENCODED_TEXT, pubKey);
            if (signatureValid) {
                List<String> strings = decodeTokenParts(KeyUtils.ENCODED_TEXT);
                EncryptedJWT encryptedJWT = NimbusWorkflow.decryptInputJwe(strings.get(1), privKey);
            }


            System.out.println(signatureValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static EncryptedJWT decryptInputJwe(String jwe, RSAPrivateKey privateKey) {
        try {
            System.out.println("Jwt encrypted string: " + jwe + "\n");
            String[] split = jwe.split("\\.");

            EncryptedJWT encryptedJWT = new EncryptedJWT(
                    new Base64URL(split[0]),
                    new Base64URL(split[1]),
                    new Base64URL(split[2]),
                    new Base64URL(split[3]),
                    new Base64URL(split[4]));

            //Decrypt JWT
            RSADecrypter decrypter = new RSADecrypter(privateKey);
            encryptedJWT.decrypt(decrypter);

            return encryptedJWT;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean isSignatureValid(String token, RSAPublicKey publicKey) {
        // Parse the JWS and verify its RSA signature
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            return signedJWT.verify(verifier);
        } catch (Exception e) {
            return false;
        }
    }

    public static RSAKey extractRSAKeyFromString(X509Certificate cert) {
        try {
            return RSAKey.parse(cert);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Input the X509Cert as string and returns RSAPrivateKey representation
     */
    public static RSAKey xCertificatePublicKeyExtractor(String encodedCert) {
        X509Certificate cert = X509CertUtils.parse(encodedCert);
        return extractRSAKeyFromString(cert);
    }

    //TODO Определить что это за сраный токен из 3 часте и заэнкрипченный то
    public static List<String> decodeTokenParts(String token) {
        String[] parts = token.split("\\.", 0);
        List<String> decodedParts = new ArrayList<>();

        for (String part : parts) {
            byte[] bytes = Base64.getUrlDecoder().decode(part);
            String decodedString = new String(bytes, StandardCharsets.UTF_8);
            decodedParts.add(decodedString);
            System.out.println("Decoded: " + decodedString);
        }
        return decodedParts;
    }
}
