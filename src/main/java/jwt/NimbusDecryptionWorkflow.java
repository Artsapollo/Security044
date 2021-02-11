package jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jwt.dto.CardholderInformation;
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

public class NimbusDecryptionWorkflow {
    public static void main(String[] args) {
        try {
            //Extract private key from string - Done
            String privateKeyContent = KeyUtils.MGB_PRIVATE_DEC_KEY.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
//            String privateKeyContent = KeyUtils.Y_PRIVATE_KEY.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

            KeyFactory kf = KeyFactory.getInstance("RSA");

            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);

            //Extract public key from cert - Done
            RSAPublicKey pubKey = xCertificatePublicKeyExtractor(KeyUtils.MGB_PUBLIC_DEC_KEY).toRSAPublicKey();
//            RSAPublicKey pubKey = xCertificatePublicKeyExtractor(KeyUtils.Y_PUBLIC_KEY).toRSAPublicKey();

            System.out.println(privKey + "\n");
            System.out.println(pubKey);

            boolean signatureValid = NimbusDecryptionWorkflow.isSignatureValid(KeyUtils.M_ENCODED_TEXT, pubKey);
//            boolean signatureValid = NimbusDecryptionWorkflow.isSignatureValid(KeyUtils.Y_ENCODED_TEXT, pubKey);
            if (signatureValid) {
                List<String> strings = decodeTokenParts(KeyUtils.M_ENCODED_TEXT);
//                List<String> strings = decodeTokenParts(KeyUtils.Y_ENCODED_TEXT);

                EncryptedJWT encryptedJWT = NimbusDecryptionWorkflow.decryptInputJwe(strings.get(1), privKey);
                JWTClaimsSet jwtClaimsSet = encryptedJWT.getJWTClaimsSet();

                String cardholderInfoString = jwtClaimsSet.getClaim("cardholderInfo").toString();
                System.out.println(cardholderInfoString);


                ObjectMapper mapper = new ObjectMapper();
                CardholderInformation cardholderInformation = mapper.readValue(cardholderInfoString, CardholderInformation.class);
                System.out.println(cardholderInformation);
            }

            System.out.println(signatureValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

/*
MGB
Jwt encrypted string: {"iat":1613058311,"jti":"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.zyUUoEOUWzanp9-pk4ty8MBxG4jwc5T3yTgPeLCHAMpLcnCUrF0i8y0nhg_e3ACSyh0FsD6ZWrNsRmgQFJx_BSIDTt246_-rcNqPFo9KqhyEAZyR1AcrM_P58kRwVQej-pXjhBTeDLPI6_0hGdBcw6JBi8k-k400QNOCSitFrMWkJtie_Q14zDWe82ypFOZUMrOkpAeDdFmBxIfrsi63IWK0RQzZVHP4TxaQ93yAtyfabQ3IiiTouGV0rLYIy8w0D_IYI5n7C7rjwsF_79UhTjlG1AFnhjVBRmhIHNVzmK0qiH-v34EAVWcrtalKluqZFNWbbCiHqtmaILdxtugZ5Q.mTloNL8instUMdq1.gyU9i2oLsetXjS5VuikYX7xCbWLQNGke8jvAY_5r0-XhRBFjPDTKyzUavlThY3npZbPVTLwyZ97XAh9MJdHZsC28FPP6ImiLtwUvfe8EEwxdzLRUSK-o5KtoyXcuXNyB1PVpds-u51UXSkViZyIo2nKPb9DrFA3pl-azWp-cucd-wKsx0KJRjcM1SQ3HnwDW6Wd5DmNxzAzcKIzBlvx1J7SIQEowAz9thxBvd-LXsfZbMejLECJsv57IrJVsc8XYc3vsE5nHTmV7lOXwgVTTDQzY29bQv_Q_azaNQxEZOrym_5nrfar5uBUidLGBBM_pMTF2Ty5SmQa0lTZtdbsPWFUtxVvHCXSV8s9R5JTIQkgX0dX8QSPIv7khnH8j5wl3yKRJ3a3Zq-kHIl3nLMW7jyZEXurOC6SlYTxB9lfIkDCWf9gb4a519h2iA8er8Xt6xEKwRm_rjD0EChWkvSsvpShOQ9e6qQQ9Q23fp2Ax36EZIV7T98sUBnVCL_BORHRzAK_2ey5fKlwwboBPQ_wCXMEfX7JUhcBxtVdi_96YVaWiyGxLupKTCghXcNpqC6KhfZTsp-LFLtHJ7Ewfmei6SnsZzQaQXlXlvU01kJYQylgsj3F1eXj2hpO7wO9r0XUSKgGbmjB855Q8_7hgyO-P1WLjuiUp35kiUdAINcn7olAZok81CltE9l_aKcLpaqdWIfKK3rrWFbmW.o-diPrUHPyWKZw3GkqFBtQ"}

Y
Jwt encrypted string: eyJ0eXAiOiJKT1NFIiwiZW5jIjoiQTI1NkdDTSIsImlhdCI6MTU2MzI2NTcwNCwiYWxnIjoiUlNBLU9BRVAtMjU2Iiwia2lkIjoiWU9VUl9KV0VfS0VZX0lEIn0.Quvd5hnC8Y1v9fz7cEIpXsXedcwOPJnkC70UGMo5DKmxd37q9kc1YtV5xnUQ836thHEgxnqRCjEbbNgQPDXAJ9lu3ZVDttag6_U3rOagTJLq7zJJwhVtog17sVr9kXWa1Rsy2cu6s3WDPMr5WXlos9Fq6I6GW_9WMZOzFFwmvfhs2-2s6isZh7H_kvXVakARWfb0tS0a7niAwCwKFZHuDpw6bnZT-fguel7OsN0pSEXyq1aDFfx9NonJagbWwouB1LQMbQ9Hhfbk0Qe-e6oaO12n7LtC6atxeJ_IhrsOslGLizMy9yrNxNzAK1GJj_DlZZS3Du2C1MCd8ny7xZblaQ.xIoYXmEqNxiw__qT.RTieqvFXHfue8fhvdWepBL3ul-ZH1GfE2Pzy0pvF2bGgK884htS5pbUZIT48hiuGNaWLJ3diGgOgB9BtAcJXVWL32IrdWkKabD5C5TaiXfXmINhFztuh05IsuWPLVvAP5iXM3xNu_NTEUonP10mPsFfaT2SrO-Atm9Iz2AWmUqKLNsp6Az4QW-4YUQpeJBuoykqD5GVesPlEdDby7w7aivvx9Z0nAw0aM-ffp-1Lv3-Cu90E9xfnh8GXLTE7T-iVPENEFi-D1bH8nZ1aOmT4TkR3amoFEDFeDx2CZC4h-uE-Gc55JYahAU9rQbhvEPnLRNKn0W7DmMHae_DMN9FHZy6FJyTGJ2AGixBWPRtTNjD-bV_nPuJxErc6mWnomkpBrHFUNgFVF8cjznLhSOfg9ahFPI7B1Muh2FIurmEGShbr2eyqRQ9Z87T6AjUural5lcc7DFKPwvvGehKilj54_Xz-9_bQnGSrRCEh2eXepPfhPQSzMpk2ku1EYvbje-yjnLQaoMCr5mC7DhGz7hZCyeZ0vmevQItZDRvzKcSD2Ayzv8PF6-1bPU72a4UNaAshGxKCYbzGtf6uBKuwtzYxoSBojaHB2RE5ibAOu3ZWt7GWzn54u6NavHCS0JVUHyZ-rLipavKxadykdO-4G8U4Ek8sX-bFlSDImTnudte2MvpV7bGTdAMlPxyIAgl3NG7O0p4NcuzhOFuQndlUAfYPjjy_04rHHVqwZw0tJ_fnE2PmMpxGByL5NT9kzBCfcZoeI2-ZF-Y1pInhqNamoG7e4f8x3AEvdeUISH0c5K1ktzxj0OdjCSHPgNoH2ECSLKUPmxuHrdxqCvDlqFAEW-Cw6DwPhMCeGrgXYbsHxjWvNRR5tblY2hr_wJ786wWP5EzTe-PFfni002T2mLpfgfUZrI-nliKkgOhlgv-xvNwN8WhB-LuSAZPJgj3FQLYepp9PSHsKaAGgSta2MCAvytrdxVORdyQsQYbVArFBVlsPiLPDyI89iX40TV7eqKvV8R47QtwkxvEhdYMEKTcsQOIDaQ-6UVLtFHeugSugkilLDdlvdavAeT30VUNcgo_SxzET9L1b7hQL7b6bCh7ePyjLTCYLOTC-i3vgbZg8BLyMxZiO2soKOdk6RDWHcuFqeNSXqCgjqGHCC1H7GTbT4aPoAFADN9Npoy8KLaP_Xd2M8dC2BhwKSFE9fEO-yc8LRLMm09AmU476mhvWBuad3JojL0EtngLiMytA9QF73TJ02n3MKVZoA-eWRkIYg1rcSrUC3f3GGCNsaxHsNz2nJYy6j5LCPS-UlmU1sRAMlrUmlO0FQlDIif93tKbHasUmoPqlChNr_pudpd56s3MbF-qLGfXHuWpqiI9y9eXcgquqHhdd2UbCbIwxkw.cX8mHAQ7_OokAXkaDv-Fpw

 */
    public static EncryptedJWT decryptInputJwe(String jwe, RSAPrivateKey privateKey) {
        try {
            System.out.println("Jwt encrypted string: " + jwe + "\n");
            String[] split = jwe.split("\\.", 0);

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
//JWS - all 3 pars are encrypted
    /*
    Yevheniy's JWS HEADER
    {
 "kid": "ypylypen",
 "cty": "JWE",
 "typ": "JOSE",
 "alg": "PS256"
}
decodeTokenParts Y:
JWS HEADER
JWS ENCRYPTED PAYLOAD
JWS SIGNATURE

decodeTokenParts MGB:
JWS HEADER
JWS NOT ENCRYPTED PAYLOAD with encrypted claim
JWS SIGNATURE
     */
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
