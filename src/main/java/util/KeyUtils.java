package util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.shaded.json.parser.ParseException;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyUtils {
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static RSAKey generateRsaKeys(String kid, KeyUse keyUse) {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID(kid)
                    .keyUse(keyUse)
                    .generate().toRSAKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void extractKeyFromString(String publicK) {
        try {
            byte[] publicBytes = Base64.getDecoder().decode(publicK);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
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

    /**
     * Input the private key as string and returns RSAPrivateKey representation
     */
    public static RSAKey prvExtract(String privateKey) {
        try {
            return RSAKey.parse(privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

//    public static boolean isSignatureValid(String token, String publicKey) {
//        // Parse the JWS and verify its RSA signature
//        SignedJWT signedJWT;
//        try {
//            signedJWT = SignedJWT.parse(token);
//            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
//            return signedJWT.verify(verifier);
//        } catch (Exception e) {
//            return false;
//        }
//    }

    public final static String PUBLIC_KEY = "-----BEGIN CERTIFICATE-----" +
            "MIIEszCCA5ugAwIBAgIJAOsA/5RhU4DTMA0GCSqGSIb3DQEBBQUAMIGXMQswCQYD" +
            "VQQGEwJVQTETMBEGA1UECBMKU29tZS1TdGF0ZTENMAsGA1UEBxMES3lpdjENMAsG" +
            "A1UEChMEVmlzYTEYMBYGA1UECxMPVlRTIEludGVncmF0aW9uMRkwFwYDVQQDExBZ" +
            "ZXZoZW4gUHlseXBlbmtvMSAwHgYJKoZIhvcNAQkBFhF5cHlseXBlbkB2aXNhLmNv" +
            "bTAeFw0xODA2MjcxMzUxMjFaFw0yODA2MjQxMzUxMjFaMIGXMQswCQYDVQQGEwJV" +
            "QTETMBEGA1UECBMKU29tZS1TdGF0ZTENMAsGA1UEBxMES3lpdjENMAsGA1UEChME" +
            "VmlzYTEYMBYGA1UECxMPVlRTIEludGVncmF0aW9uMRkwFwYDVQQDExBZZXZoZW4g" +
            "UHlseXBlbmtvMSAwHgYJKoZIhvcNAQkBFhF5cHlseXBlbkB2aXNhLmNvbTCCASIw" +
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN4n1L+XP+1seNuX8yfhLLDFJ4ry" +
            "3OJwjh1IVfukH1PASt3anSuxBHLV+Bpqnq/1sirMhkSA6svKbKLIoXrn5Dazp/kc" +
            "GBOHt1OgtsRMoF3TYGqU1pLQUQg4OqoYZG7Gc/qGzcqbSQWZLcjWrhpPQix+3exe" +
            "KIe6KkxYG3LY1+6S1/LGOZrqOsQB2Ow8DIeT6YbUdYazSYix/heW4LdCDnB4WP1w" +
            "SuVKwoctbuelsIpOy66xxD6T/YhkFpI80750CRLwRmlMLfbgfvfFk8OYIaVbQjby" +
            "d7Yma9NMyF5nQuf4zSREDE39P8a3bu3Tt1XyN6neYtT9fe4MSaNUwHl4sd0CAwEA" +
            "AaOB/zCB/DAdBgNVHQ4EFgQUvhv4YxrWS7xAjSCGfrbtB17V9pgwgcwGA1UdIwSB" +
            "xDCBwYAUvhv4YxrWS7xAjSCGfrbtB17V9pihgZ2kgZowgZcxCzAJBgNVBAYTAlVB" +
            "MRMwEQYDVQQIEwpTb21lLVN0YXRlMQ0wCwYDVQQHEwRLeWl2MQ0wCwYDVQQKEwRW" +
            "aXNhMRgwFgYDVQQLEw9WVFMgSW50ZWdyYXRpb24xGTAXBgNVBAMTEFlldmhlbiBQ" +
            "eWx5cGVua28xIDAeBgkqhkiG9w0BCQEWEXlweWx5cGVuQHZpc2EuY29tggkA6wD/" +
            "lGFTgNMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEA3eKDaJaP0zZ1" +
            "OSVzYXB1KDZjRHWQrqEE3yiCOcPOzQJKa6uXviYRokjfqLdLcewjyoe6dbhxh+6i" +
            "YBXjSCeGUo0R3T+dgnB5g4PtRmLBP8IMjvb7kBPkCRP6cjUBKJ4BKZII2tTjWGwK" +
            "D2s0eSp+r6ynjsEzuosi6lBukzewGwBIF5FE82b7InJNNZsKrgmWyy7KhGTNFgzG" +
            "bM3vMGBFgzdn22fbBGmXLaH2SPOV0gSx0zNFXaQvB8BC1uSpP+UMjqJtWiLiZHsd" +
            "t08KK029OPI56rcpjFCBrZq2opdq2d7x+dd/F4+/ZxvhJq26BlH8U0bCGhxtJyM9" +
            "fycDYJtaIA==" +
            "-----END CERTIFICATE-----";
    public final static String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----" +
            "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDeJ9S/lz/tbHjb" +
            "l/Mn4SywxSeK8tzicI4dSFX7pB9TwErd2p0rsQRy1fgaap6v9bIqzIZEgOrLymyi" +
            "yKF65+Q2s6f5HBgTh7dToLbETKBd02BqlNaS0FEIODqqGGRuxnP6hs3Km0kFmS3I" +
            "1q4aT0Isft3sXiiHuipMWBty2Nfuktfyxjma6jrEAdjsPAyHk+mG1HWGs0mIsf4X" +
            "luC3Qg5weFj9cErlSsKHLW7npbCKTsuuscQ+k/2IZBaSPNO+dAkS8EZpTC324H73" +
            "xZPDmCGlW0I28ne2JmvTTMheZ0Ln+M0kRAxN/T/Gt27t07dV8jep3mLU/X3uDEmj" +
            "VMB5eLHdAgMBAAECggEBAJoOFwuRkGRNz3XAZn9mOD6RSb2icyiYEwUdb3rkslC6" +
            "zXARtOJijAoydS2keEzfXeEuGYIRwED4K+Oqq8h2XJzOcxJduBh7Cdd1YKi51o+a" +
            "EId4lWAUE81WaOAhsCvddPnrV3RDwRyfv89BiFR4WBRRGgZauVJ99+0fQFGhLASl" +
            "B1erxhGBPsT/NLyLCyicc/08MEB4/PzG9OqzE1tPmoMHuOTn0uIAlOOyPjT598CN" +
            "k9LK5ipBLlpuHeApot/2VXA8T8pzUfNyjfqJSJqndZY0YDgdQofeT9/xei1rjhjI" +
            "WTojSKzBjdwQE6lLM6K2OOVFOqkK3mHIgfkfL1gbZwUCgYEA78a9iMNIY9dulBBt" +
            "8d+nmETv7BFaSWqcwqTbpGnLHOyGrORs9Kq+wjbLra3MWFP/xn6utN0ZER2Dv5G2" +
            "iWbHU7svcF2d93CO/dzjCQuCCyMkukO6AA6VXPixNA0sY3ApAx3dN7isgK12v8UY" +
            "GRcX5kp3abkikDaPS+aIquiY9ocCgYEA7S/f/RlzhiV/CAY6XAuFbyFvS8HTHUCb" +
            "herhxpmpW/Ons3NmlD4fBX01P+AqgtVouKJFn+05x+PdDdtYJSrYuMxW633WQsn0" +
            "sCO3RNTki37OJ/CH7XYGnmtLFvT4Ogyhna4HgVs+g8wZRanVu5rYVlgBZ/Dfd2HL" +
            "huPpUnqUiXsCgYEAgOtlmvQMpwn8/YU76BGtxdRC/7VwywqUkJ8dLXBocfvGiY0j" +
            "/AUWHcxihNZuiYtYebxBaSN7x9ULsmPBNm1ZfO6nGg5r0c/mQh6Sv5k9aYmSxMeH" +
            "aWJt8pgQhwESPcDffDqBZ+VWcrVRpNhvFYZyJjMhs2mEaO+86j1gfCwlml8CgYEA" +
            "wRz8osbJH0yCLBdeBrk+r+eqBSVPbP7AYX2Gy7sqf/pW7S2lNEeL3F1AMLykABgf" +
            "hkxgocB1DgHBZlnTX5eOEpAUqPGwtHpX5d1+huVLGyRoV25oTXeOFgfHgG59eE32" +
            "fDpIVBLlSEuxu912bqO5RjurEWS1nS6blj0UKBozu+cCgYEAuFgD2WB6MO2Cqcm9" +
            "n+eWAeH6xTdRLiSp4wVRHxrL90ADYCHUVSXUaV5rVEYzq1pD+p9gX7zYXpEySWJL" +
            "TNT7kNSF/iuVsjJ9ih6aBRY65rk8F/ru22MUmCeIjey+wm1yvnlucJ8WmZJW5xUp" +
            "VWbmXIhIVbE/tMsDkM5GqPh25+Y=" +
            "-----END PRIVATE KEY-----";

    public final static String ENCODED_TEXT = "eyJraWQiOiJ5cHlseXBlbiIsImN0eSI6IkpXRSIsInR5cCI6IkpPU0UiLCJhbGciOiJQUzI1NiJ9.ZXlKMGVYQWlPaUpLVDFORklpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltbGhkQ0k2TVRVMk16STJOVGN3TkN3aVlXeG5Jam9pVWxOQkxVOUJSVkF0TWpVMklpd2lhMmxrSWpvaVdVOVZVbDlLVjBWZlMwVlpYMGxFSW4wLlF1dmQ1aG5DOFkxdjlmejdjRUlwWHNYZWRjd09QSm5rQzcwVUdNbzVES214ZDM3cTlrYzFZdFY1eG5VUTgzNnRoSEVneG5xUkNqRWJiTmdRUERYQUo5bHUzWlZEdHRhZzZfVTNyT2FnVEpMcTd6Skp3aFZ0b2cxN3NWcjlrWFdhMVJzeTJjdTZzM1dEUE1yNVdYbG9zOUZxNkk2R1dfOVdNWk96RkZ3bXZmaHMyLTJzNmlzWmg3SF9rdlhWYWtBUldmYjB0UzBhN25pQXdDd0tGWkh1RHB3NmJuWlQtZmd1ZWw3T3NOMHBTRVh5cTFhREZmeDlOb25KYWdiV3dvdUIxTFFNYlE5SGhmYmswUWUtZTZvYU8xMm43THRDNmF0eGVKX0locnNPc2xHTGl6TXk5eXJOeE56QUsxR0pqX0RsWlpTM0R1MkMxTUNkOG55N3haYmxhUS54SW9ZWG1FcU54aXdfX3FULlJUaWVxdkZYSGZ1ZThmaHZkV2VwQkwzdWwtWkgxR2ZFMlB6eTBwdkYyYkdnSzg4NGh0UzVwYlVaSVQ0OGhpdUdOYVdMSjNkaUdnT2dCOUJ0QWNKWFZXTDMySXJkV2tLYWJENUM1VGFpWGZYbUlOaEZ6dHVoMDVJc3VXUExWdkFQNWlYTTN4TnVfTlRFVW9uUDEwbVBzRmZhVDJTck8tQXRtOUl6MkFXbVVxS0xOc3A2QXo0UVctNFlVUXBlSkJ1b3lrcUQ1R1Zlc1BsRWREYnk3dzdhaXZ2eDlaMG5BdzBhTS1mZnAtMUx2My1DdTkwRTl4Zm5oOEdYTFRFN1QtaVZQRU5FRmktRDFiSDhuWjFhT21UNFRrUjNhbW9GRURGZUR4MkNaQzRoLXVFLUdjNTVKWWFoQVU5clFiaHZFUG5MUk5LbjBXN0RtTUhhZV9ETU45RkhaeTZGSnlUR0oyQUdpeEJXUFJ0VE5qRC1iVl9uUHVKeEVyYzZtV25vbWtwQnJIRlVOZ0ZWRjhjanpuTGhTT2ZnOWFoRlBJN0IxTXVoMkZJdXJtRUdTaGJyMmV5cVJROVo4N1Q2QWpVdXJhbDVsY2M3REZLUHd2dkdlaEtpbGo1NF9Yei05X2JRbkdTclJDRWgyZVhlcFBmaFBRU3pNcGsya3UxRVl2YmplLXlqbkxRYW9NQ3I1bUM3RGhHejdoWkN5ZVowdm1ldlFJdFpEUnZ6S2NTRDJBeXp2OFBGNi0xYlBVNzJhNFVOYUFzaEd4S0NZYnpHdGY2dUJLdXd0ell4b1NCb2phSEIyUkU1aWJBT3UzWld0N0dXem41NHU2TmF2SENTMEpWVUh5Wi1yTGlwYXZLeGFkeWtkTy00RzhVNEVrOHNYLWJGbFNESW1UbnVkdGUyTXZwVjdiR1RkQU1sUHh5SUFnbDNORzdPMHA0TmN1emhPRnVRbmRsVUFmWVBqanlfMDRySEhWcXdadzB0Sl9mbkUyUG1NcHhHQnlMNU5UOWt6QkNmY1pvZUkyLVpGLVkxcEluaHFOYW1vRzdlNGY4eDNBRXZkZVVJU0gwYzVLMWt0enhqME9kakNTSFBnTm9IMkVDU0xLVVBteHVIcmR4cUN2RGxxRkFFVy1DdzZEd1BoTUNlR3JnWFlic0h4ald2TlJSNXRibFkyaHJfd0o3ODZ3V1A1RXpUZS1QRmZuaTAwMlQybUxwZmdmVVpySS1ubGlLa2dPaGxndi14dk53TjhXaEItTHVTQVpQSmdqM0ZRTFllcHA5UFNIc0thQUdnU3RhMk1DQXZ5dHJkeFZPUmR5UXNRWWJWQXJGQlZsc1BpTFBEeUk4OWlYNDBUVjdlcUt2VjhSNDdRdHdreHZFaGRZTUVLVGNzUU9JRGFRLTZVVkx0RkhldWdTdWdraWxMRGRsdmRhdkFlVDMwVlVOY2dvX1N4ekVUOUwxYjdoUUw3YjZiQ2g3ZVB5akxUQ1lMT1RDLWkzdmdiWmc4Qkx5TXhaaU8yc29LT2RrNlJEV0hjdUZxZU5TWHFDZ2pxR0hDQzFIN0dUYlQ0YVBvQUZBRE45TnBveThLTGFQX1hkMk04ZEMyQmh3S1NGRTlmRU8teWM4TFJMTW0wOUFtVTQ3Nm1odldCdWFkM0pvakwwRXRuZ0xpTXl0QTlRRjczVEowMm4zTUtWWm9BLWVXUmtJWWcxcmNTclVDM2YzR0dDTnNheEhzTnoybkpZeTZqNUxDUFMtVWxtVTFzUkFNbHJVbWxPMEZRbERJaWY5M3RLYkhhc1Vtb1BxbENoTnJfcHVkcGQ1NnMzTWJGLXFMR2ZYSHVXcHFpSTl5OWVYY2dxdXFIaGRkMlViQ2JJd3hrdy5jWDhtSEFRN19Pb2tBWGthRHYtRnB3.prnxd9W_l9-Ql5KyWIz3q7O_h-sNPuc6jYQdFdg5F6Lu92x9hzjcXlBuQJxxkiwFvnKaeFjiXm818ZXutooCjbAPx0deaFHHJ6OPEe_yTU5pF147jdPxAieTX4XKWGriVmP5VCbrGJg1u7itTqZ8JAiqAjcR4JNO0k6eHFLMp2253974OrhA7XET4QJfVU6SAAzWB7rOSsPp74QSwxWakjNU0RbfCcoJBVMkM0ipc4RxXPsFQ6ZBpiR6zOVVItLG8bTvr0ISvm85k1I9o254acDOMXTtZyv28qG8IfCp8kNGiwM7BdM3MKl8yEm1xB448qAug-3t6mfFU3JFIRQzOg";

}
