package jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

public class TokenService {

    /*
        Replace all spaces (" ", "") and "Begin" "End" headers and footers from cert or key before using them;
     */

    //uses my public key to verify signature.
    private final static String PUB_KEY = "";

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
    public static String createJWT(String id, String issuer, String subject, long ttlMillis, PrivateKey aPrivate ) {

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
        }catch (Exception e){
            e.printStackTrace();
        }
        return claims;
    }


}
