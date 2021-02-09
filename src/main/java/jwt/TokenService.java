package jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jdk.nashorn.internal.runtime.ECMAException;
import util.KeyUtils;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Nimbus JOSE + JWT
 * Hint: Replace all spaces (" ", "") and "Begin" "End" headers and footers from cert or key before using them;
 */
public class TokenService {

    //uses my public key to verify signature.
    private final static String PUB_KEY = "";

    //use my private key to decrypt data
    private final static String PRIVATE_KEY = "";

    /**
     * Full lifecycle JWS+JWE
     * INPUT:  requestData, senderPrivateJWK, receiverPublicJWK
     */
    public static void createFullJwt() {
        //SIGN AND ENCRYPTION

        //Отправитель
        //Generate sender RSA key pair, make public key available to recipient
        RSAKey senderPrivateJWK = KeyUtils.generateRsaKeys("123", KeyUse.SIGNATURE);     //Using to create JWT and sign it
        RSAKey senderPublicJWK = senderPrivateJWK.toPublicJWK(); //Using to checkSignature

        //Получатель
        //Generate recipient RSA key pair, make public key available to sender:
        RSAKey receiverPrivateJWK = KeyUtils.generateRsaKeys("456", KeyUse.ENCRYPTION); //Using to decrypt Jwe
        RSAKey receiverPublicJWK = receiverPrivateJWK.toPublicJWK(); //Using to encrypt Jwe

//        The sender signs the JWT with their private key and then encrypts to the recipient:

        // Create JWT
        SignedJWT signedJWT = createJwt(senderPrivateJWK); //тут просто достаются засеченные данные из ключа
        //Sign the JWT
        signJwt(signedJWT, senderPrivateJWK); //JWS

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = createJweWithJwt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, "JWT", signedJWT);
        //Encrypt the JWT
        encryptJwe(jweObject, receiverPublicJWK); //JWE

        String token = jweObject.serialize();
        System.out.println("Created JWE: " + token);

        //Decrypt
        readJwt(token, receiverPrivateJWK, senderPublicJWK);

    }

    /**
     * Decrypt JWT lifecycle
     * INPUT: jweString, receiverPrivateJWK, senderPublicJWK
     */
    public static void readJwt(String token, RSAKey receiverPrivateJWK, RSAKey senderPublicJWK) {
        //DECRYPTION
        SignedJWT signedJWT = decryptJwt(token, receiverPrivateJWK); //JWE
        // Verify the signature
        boolean verify = checkJwtSignature(signedJWT, senderPublicJWK); //JWS
        System.out.println("Is signature verified: " + verify + "\n");

        try {
            System.out.println("Decrypted signed jwt: " + signedJWT.getJWTClaimsSet() + "\n");
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }


    public static SignedJWT createJwt(RSAKey senderJWK) {
        return new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderJWK.getKeyID()).build(),
                new JWTClaimsSet.Builder()
                        .subject("Artsapollo")
                        .issueTime(new Date())
                        .issuer("www.pravda.ua")
                        .build());
    }

    public static void signJwt(SignedJWT signedJWT, RSAKey senderPrivateJWK) {
        try {
            signedJWT.sign(new RSASSASigner(senderPrivateJWK));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static JWEObject createJweWithJwt(JWEAlgorithm jweAlgo, EncryptionMethod encryptMethod, String contentType, SignedJWT signedJWT) {
        return new JWEObject(
                new JWEHeader.Builder(jweAlgo, encryptMethod)
                        .contentType(contentType)
                        .build(),
                new Payload(signedJWT));
    }

    public static void encryptJwe(JWEObject jweObject, RSAKey recipientPublicJWK) {
        try {
            jweObject.encrypt(new RSAEncrypter(recipientPublicJWK));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static SignedJWT decryptJwt(String token, RSAKey recipientPrivateJWK) {
        SignedJWT signedJWT = null;

        try {
            // Parse the JWE string
            JWEObject jweObject = JWEObject.parse(token);

            // Decrypt with private key
            jweObject.decrypt(new RSADecrypter(recipientPrivateJWK));

            // Extract payload
            signedJWT = jweObject.getPayload().toSignedJWT();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return signedJWT;
    }

    public static boolean checkJwtSignature(SignedJWT signedJWT, RSAKey senderPublicJWK) {
        boolean verify = false;
        try {
            verify = signedJWT.verify(new RSASSAVerifier(senderPublicJWK));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return verify;
    }

    /**
     * JSON Web Token (JWT) with RSA encryption
     * THIS IS WHAT WE NEED
     */
    public static void encryptDecryptJwe() {
        try {
            KeyPair keyPair = KeyUtils.generateKeyPair();

            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();


            // Compose the JWT claims set
            Date now = new Date();

            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                    .issuer("https://openid.net")
                    .subject("alice")
                    .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                    .expirationTime(new Date(now.getTime() + 1000 * 60 * 10)) // expires in 10 minutes
                    .notBeforeTime(now)
                    .issueTime(now)
                    .jwtID(UUID.randomUUID().toString())
                    .build();


            System.out.println("JwtClaims: " + jwtClaims.toJSONObject() + "\n");

            // Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

            // Create the encrypted JWT object
            EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);


            // Create an encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);

            jwt.encrypt(encrypter);

            String jwtString = jwt.serialize();
            System.out.println("Encrypted jwt string: " + jwtString + "\n");

            jwt = EncryptedJWT.parse(jwtString);

            //Decrypt JWT
            RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);

            jwt.decrypt(decrypter);

            // Retrieve JWT claims
            System.out.println("JWT CLAIMS: \n");
            System.out.println(jwt.getJWTClaimsSet().getIssuer());
            System.out.println(jwt.getJWTClaimsSet().getSubject());
            System.out.println(jwt.getJWTClaimsSet().getAudience());
            System.out.println(jwt.getJWTClaimsSet().getExpirationTime());
            System.out.println(jwt.getJWTClaimsSet().getNotBeforeTime());
            System.out.println(jwt.getJWTClaimsSet().getIssueTime());
            System.out.println(jwt.getJWTClaimsSet().getJWTID());
            System.out.println("");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static EncryptedJWT decryptInputJwe(String jwe, String privateKey) {
        try {
            System.out.println("Jwt encrypted string: " + jwe + "\n");
            RSAPrivateKey rsaPrivateKey = RSAKey.parse(privateKey).toRSAPrivateKey();
            System.out.println("RSAPrivateKey: " + rsaPrivateKey + "\n");

            String[] split = jwe.split("\\.");

            EncryptedJWT encryptedJWT = new EncryptedJWT(
                    new Base64URL(split[0]),
                    new Base64URL(split[1]),
                    new Base64URL(split[2]),
                    new Base64URL(split[3]),
                    new Base64URL(split[4]));

            //Decrypt JWT
            RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);
            encryptedJWT.decrypt(decrypter);

            return encryptedJWT;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean isSignatureValid(String token, String publicKey) {
        // Parse the JWS and verify its RSA signature
        SignedJWT signedJWT;
        try {
            RSAPublicKey rsaPublicKey = RSAKey.parse(publicKey).toRSAPublicKey();
            signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);
            return signedJWT.verify(verifier);
        } catch (Exception e) {
            return false;
        }
    }
}
