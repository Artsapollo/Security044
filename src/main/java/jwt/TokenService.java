package jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

public class TokenService {

    /*
        Replace all spaces (" ", "") and "Begin" "End" headers and footers from cert or key before using them;
     */

    //uses my public key to verify signature.
    private final static String PUB_KEY = "eyJraWQiOiJ5cHlseXBlbiIsImN0eSI6IkpXRSIsInR5cCI6IkpPU0UiLCJhbGciOiJQUzI1NiJ9.ZXlKMGVYQWlPaUpLVDFORklpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltbGhkQ0k2TVRVMk16STJOVE01TUN3aVlXeG5Jam9pVWxOQkxVOUJSVkF0TWpVMklpd2lhMmxrSWpvaVdVOVZVbDlLVjBWZlMwVlpYMGxFSW4wLmpvNzlrOUNLTXRyV3Z4bE1SekpYSlZzUVFtR2VDWnc4WFhBd0p1eDVkMkUwNkhHVHFsMXN6M3pVVUtpLXNBWUJRNENudGs2S1hZR0ZkaXdpR1YwMTkzV3ZaaEpEdVU5MHBWdlFMSk1sOHVCWjdFZGc3aWxMbnFZRWNPSG11SmVERVhZVmxpaHhqemRJc3B5ek1XUmtVMXlfc2dUYjJ5NXg2dFItTXZqbjhMVFpQUWxmaS1JaXNnUDRqVXFmLUpkLWhnZ2JRLUN3OGhrNTdEZk9FbnY1VkswcDllc3IteDFXSWRzYmdEUlRyVXZodlEzWWJ2ZDVJLWxkZmNocmUwNTJ2OVRtRFJ1R0lvSHZzejBBLXJCTmxuMGd1TVdyd1lVSzFxWWVjRXpydTZWSVFNSUNYdXZaZ2diczBnSEh1TTE2TFJIdGp1RlJQRUxLR1UtZ2VJY2dNZy5lQUk3bHBwbWFJaDVtWERkLnlkM2Z6R3JLZU5pdWd0ZEhCUHhmaTRDWk5LLXZKUXNrdFhqaUh0ZDlRX0FENDU1M29NQlR1cjZsZFhWSGRLcXZUdUlaVWJMSkxRWDcxNFBVTmNKbDcyU1kxNy1tT0x0MXhxM0RvLWdaU0Y0Q1hTLVlDaWNQcEwzcXRBdUx0UzNSd2ZrNUhIRF81U1VZeWowN3lybG4zdV9EUHU0cWRFdzZCdHlKUHFROGZtYmV6MlpXU2hqR2JOS1QuWm5kUlNaei1sUVBGSkp0by1pbmxLdw.rBvBbuNiDhRaSMw7MpF1EDPybJseOSSvmitDviFvOZ9_PH_yh7ze6gYhA6-JDR6ubMpPCTf3CbKFDw1dqaO3BY1JoWVXXzqkXdjWr7jE5fSaJU5M-47Zn0VJh7aq-P4rkOFyyUBizKTcj5k0DD8WOYVGDvVYOt2lfbh6Ky3gNkF1a-swIWZaKZl-zywR46BkmriG0IbNij0KY3sdU21UT0Wbo-kiFFREOYeu4zNDSRGorQAvCijQkPY4Moto7AQaBZxmGLIk5HfXvliu7Mj6JQPhNjfltUgl-NEag2iN0ajDcyj9z49U0VQfwjVg2AE4VJV-St_kGZ1WpJTyYVlYkQ";

    //use my private key to decrypt data
    private final static String PRIVATE_KEY = "";


    private static final String SECRET_KEY = "Brace yourself, I'll take you on a trip down memory lane " +
            "This is not a rap on how I'm slingin' crack or move cocaine This is cul-de-sac and plenty Cognac and major pain";

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * createJWT() method does the following:
     * Sets the hashing algorithm
     * Gets the current date for the Issued At claim
     * Uses the SECRET_KEY static property to generate the signing key
     * Uses the fluent API to add the claims and sign the JWT
     * Sets the expiration date
     */
    public static String createJWT(String id, String issuer, String subject, long ttlMillis, PrivateKey aPrivate) {

        //The JWT signature algorithm we will be using to sign the token
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        long nowMillis = System.currentTimeMillis();

        //Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder()
                .setHeaderParam("kid", "myKeyId")
                .setId(id)
                .setIssuedAt(new Date(nowMillis))
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(aPrivate);

        //if it has been specified, let's add the expiration
        if (ttlMillis > 0) {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        //Builds the JWT and serializes it to a compact, URL-safe string
        return builder.compact();
    }

    public static Claims confirmSignatureJWT(String jwt, PublicKey aPublic) {
        //This line will throw an exception if it is not a signed JWS (as expected)
        Claims claims = null;
        String plainText = null;
        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(aPublic)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return claims;
    }

    public static void encryptDecryptJwe() {
        KeyPair keyPair = generateKeyPair();

        RSAPublicKey rsaPublicKey = null;
        RSAPrivateKey rsaPrivateKey = null;
        try {
            rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

            //generate public key from private key
//            RSAPrivateCrtKey privk = (RSAPrivateCrtKey) privateKey;
//            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
//            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

        } catch (Exception e) {
            e.printStackTrace();
        }


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
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

        // Create the encrypted JWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);


        // Create an encrypter with the specified public RSA key
        RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);
        try {
            jwt.encrypt(encrypter);

            String jwtString = jwt.serialize();
            System.out.println("Jwt encrypted string: " + jwtString + "\n");

//            String[] split = jwtString.split("\\.");
//            System.out.println("JWT compact form: \n");
//            for(String part : split){
//                System.out.println(part);
//            }
//            System.out.println();

            jwt = EncryptedJWT.parse(jwtString);

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

    public static RSAKey generateSenderRsaKeys() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID("123")
                    .keyUse(KeyUse.SIGNATURE)
                    .generate().toRSAKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static RSAKey generateRecipientRsaKeys() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID("456")
                    .keyUse(KeyUse.ENCRYPTION)
                    .generate().toRSAKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void workaroundJwsJwe() {
//        KeyPair keyPairSender = generateKeyPair();
//
//        RSAPublicKey sendPub = (RSAPublicKey) keyPairSender.getPublic();
//        RSAPrivateKey sendPrv = (RSAPrivateKey) keyPairSender.getPrivate();
//
//        KeyPair keyPairIssuer = generateKeyPair();
//
//        RSAPublicKey issPub = (RSAPublicKey) keyPairIssuer.getPublic();
//        RSAPrivateKey issPrv = (RSAPrivateKey) keyPairIssuer.getPrivate();
//
//        RSAKey sendRsaPub = new RSAKey.Builder(sendPub).build();

        //Generate sender RSA key pair, make public key available to recipient
        RSAKey senderJWK = generateSenderRsaKeys();
        RSAKey senderPublicJWK = senderJWK.toPublicJWK();

        //Generate recipient RSA key pair, make public key available to sender:
        RSAKey recipientJWK = generateRecipientRsaKeys();
        RSAKey recipientPublicJWK = recipientJWK.toPublicJWK();

//        The sender signs the JWT with their private key and then encrypts to the recipient:

        // Create JWT
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderJWK.getKeyID()).build(),
                new JWTClaimsSet.Builder()
                        .subject("Artsapollo")
                        .issueTime(new Date())
                        .issuer("www.pravda.ua")
                        .build());
        try {

            //Sign the JWT
            signedJWT.sign(new RSASSASigner(senderJWK));

            // Create JWE object with signed JWT as payload
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                            .contentType("JWT")
                            .build(),
                    new Payload(signedJWT));


            jweObject.encrypt(new RSAEncrypter(recipientPublicJWK));

            String jweString = jweObject.serialize();

            System.out.println("Created JWE: " + jweString);

            // Parse the JWE string
            JWEObject jweObject1 = JWEObject.parse(jweString);
            // Decrypt with private key
            jweObject1.decrypt(new RSADecrypter(recipientJWK));
            // Extract payload
            SignedJWT signedJWT1 = jweObject1.getPayload().toSignedJWT();
            System.out.println("Extracted payload: " + signedJWT1);

            boolean verify = signedJWT1.verify(new RSASSAVerifier(senderPublicJWK));
            System.out.println("Is signature verified: " + verify);

            System.out.println("Extracted claimsSet: " + signedJWT1.getJWTClaimsSet());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
