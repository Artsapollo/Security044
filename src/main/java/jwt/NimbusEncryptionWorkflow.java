package jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jwt.dto.Address;
import jwt.dto.CardholderInformation;
import jwt.dto.ExpirationDate;
import jwt.dto.TokenPayload;
import util.KeyUtils;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static util.KeyUtils.*;

public class NimbusEncryptionWorkflow {
    public static void main(String[] args) {

//        try {
//// Parse PEM-encoded key to RSA public / private JWK
//            JWK jwk = JWK.parseFromPEMEncodedObjects(PRIVATE_KEY);
//            JWK jwkP = JWK.parseFromPEMEncodedObjects(PUBLIC_KEY);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        TokenPayload token = buildToken();
        encryptDecryptJwe("", "", token);
    }


    /**
     * JSON Web Token (JWT) with RSA encryption
     * THIS IS WHAT WE NEED
     */
    public static void encryptDecryptJwe(String privateKey, String publicCert, TokenPayload token) {
        try {

            //Extract private key from string - Done
            String privateKeyContent = KeyUtils.MGB_PRIVATE_ENC_KEY
                    .replaceAll("\\n", "")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "");

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);

            //Extract public key from cert - Done
            RSAPublicKey rsaPublicKey = xCertificatePublicKeyExtractor(KeyUtils.MGB_PUBLIC_ENC_KEY).toRSAPublicKey();

            System.out.println("Keys: \n " + rsaPrivateKey + "\n");
            System.out.println(rsaPublicKey + "\n");

            // Compose the JWT claims set
            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                    .claim("cardholderInfo", token.getCardholderInformation())
                    .claim("riskInformation", token.getAddress())
                    .claim("expirationDate", token.getExpirationDate())
                    .build();


            // Request JWT encrypted with RSA-OAEP-256 - alf and 128-bit AES/GCM - enc
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

            // Create the encrypted JWT object
            EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);


            // Create an encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);
            jwt.encrypt(encrypter);

            String jwtString = jwt.serialize();
            System.out.println("Encrypted jwt string: " + jwtString + "\n");

//            jwt = EncryptedJWT.parse(jwtString);

            //SIGN
            JWSSigner signer = new RSASSASigner(rsaPrivateKey);

            JWSObject jwsObject = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("Artsapollo").build(),
                    new Payload(jwtString));
            jwsObject.sign(signer);

//            SignedJWT signedJWT = new SignedJWT(
//                new JWSHeader.Builder(JWSAlgorithm.PS256).keyID("Artsapollo").type(JOSEObjectType.JOSE).contentType("JWE").build(),
//                    new JWTClaimsSet.Builder()
//                            .jwtID(jwtString)
//                            .issueTime(new Date())
//                            .build());
//
//
//            // Compute the RSA signature
//            signedJWT.sign(signer);

            String jws = jwsObject.serialize();
            System.out.println("Signed jwt string: " + jws);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SignedJWT createJwt(RSAKey senderJWK) {
        return new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderJWK.getKeyID()).build(),
                new JWTClaimsSet.Builder()
                        .subject("Artsapollo")
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

    public static JWEObject createJweWithJwt(JWEAlgorithm jweAlgo, EncryptionMethod encryptMethod, String
            contentType, SignedJWT signedJWT) {
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

    private static TokenPayload buildToken() {
        CardholderInformation cardholder = new CardholderInformation();
        cardholder.setCvv2("968");
        cardholder.setName("Artsapollo");
        cardholder.setHighValueCustomer(true);

        Address address = new Address();
        address.setCity("Kyiv");
        address.setCountry("Ukraine");

        ExpirationDate date = new ExpirationDate();
        date.setYear("2021");

        return TokenPayload.builder()
                .address(address)
                .cardholderInformation(cardholder)
                .expirationDate(date)
                .build();
    }
}
