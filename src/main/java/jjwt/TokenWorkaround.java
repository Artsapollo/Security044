package jjwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

/**
 *  JJWT Token Workaround
 */
public class TokenWorkaround {
    //uses my public key to verify signature.
    private final static String PUB_KEY = "eyJraWQiOiJ5cHlseXBlbiIsImN0eSI6IkpXRSIsInR5cCI6IkpPU0UiLCJhbGciOiJQUzI1NiJ9.ZXlKMGVYQWlPaUpLVDFORklpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltbGhkQ0k2TVRVMk16STJOVE01TUN3aVlXeG5Jam9pVWxOQkxVOUJSVkF0TWpVMklpd2lhMmxrSWpvaVdVOVZVbDlLVjBWZlMwVlpYMGxFSW4wLmpvNzlrOUNLTXRyV3Z4bE1SekpYSlZzUVFtR2VDWnc4WFhBd0p1eDVkMkUwNkhHVHFsMXN6M3pVVUtpLXNBWUJRNENudGs2S1hZR0ZkaXdpR1YwMTkzV3ZaaEpEdVU5MHBWdlFMSk1sOHVCWjdFZGc3aWxMbnFZRWNPSG11SmVERVhZVmxpaHhqemRJc3B5ek1XUmtVMXlfc2dUYjJ5NXg2dFItTXZqbjhMVFpQUWxmaS1JaXNnUDRqVXFmLUpkLWhnZ2JRLUN3OGhrNTdEZk9FbnY1VkswcDllc3IteDFXSWRzYmdEUlRyVXZodlEzWWJ2ZDVJLWxkZmNocmUwNTJ2OVRtRFJ1R0lvSHZzejBBLXJCTmxuMGd1TVdyd1lVSzFxWWVjRXpydTZWSVFNSUNYdXZaZ2diczBnSEh1TTE2TFJIdGp1RlJQRUxLR1UtZ2VJY2dNZy5lQUk3bHBwbWFJaDVtWERkLnlkM2Z6R3JLZU5pdWd0ZEhCUHhmaTRDWk5LLXZKUXNrdFhqaUh0ZDlRX0FENDU1M29NQlR1cjZsZFhWSGRLcXZUdUlaVWJMSkxRWDcxNFBVTmNKbDcyU1kxNy1tT0x0MXhxM0RvLWdaU0Y0Q1hTLVlDaWNQcEwzcXRBdUx0UzNSd2ZrNUhIRF81U1VZeWowN3lybG4zdV9EUHU0cWRFdzZCdHlKUHFROGZtYmV6MlpXU2hqR2JOS1QuWm5kUlNaei1sUVBGSkp0by1pbmxLdw.rBvBbuNiDhRaSMw7MpF1EDPybJseOSSvmitDviFvOZ9_PH_yh7ze6gYhA6-JDR6ubMpPCTf3CbKFDw1dqaO3BY1JoWVXXzqkXdjWr7jE5fSaJU5M-47Zn0VJh7aq-P4rkOFyyUBizKTcj5k0DD8WOYVGDvVYOt2lfbh6Ky3gNkF1a-swIWZaKZl-zywR46BkmriG0IbNij0KY3sdU21UT0Wbo-kiFFREOYeu4zNDSRGorQAvCijQkPY4Moto7AQaBZxmGLIk5HfXvliu7Mj6JQPhNjfltUgl-NEag2iN0ajDcyj9z49U0VQfwjVg2AE4VJV-St_kGZ1WpJTyYVlYkQ";

    //use my private key to decrypt data
    private final static String PRIVATE_KEY = "";


    private static final String SECRET_KEY = "Brace yourself, I'll take you on a trip down memory lane " +
            "This is not a rap on how I'm slingin' crack or move cocaine This is cul-de-sac and plenty Cognac and major pain";


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
}
