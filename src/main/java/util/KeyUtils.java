package util;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.X509CertUtils;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
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

    public final static String MGB_PUBLIC_ENC_KEY =
            "-----BEGIN CERTIFICATE-----" +
                    "MIIDiDCCAnACCQDH2L0eSqSQejANBgkqhkiG9w0BAQsFADCBhTELMAkGA1UEBhMC" +
                    "dWsxDTALBgNVBAgMBGt5aXYxDTALBgNVBAcMBGt5aXYxHDAaBgNVBAoME0RlZmF1" +
                    "bHQgQ29tcGFueSBMdGQxEzARBgNVBAMMCmFydHNhcG9sbG8xJTAjBgkqhkiG9w0B" +
                    "CQEWFmxlbWVzaGtvYXRAbWVnYWJhbmsudWEwHhcNMjEwMjExMTQ1NDI3WhcNMjEw" +
                    "MzEzMTQ1NDI3WjCBhTELMAkGA1UEBhMCdWsxDTALBgNVBAgMBGt5aXYxDTALBgNV" +
                    "BAcMBGt5aXYxHDAaBgNVBAoME0RlZmF1bHQgQ29tcGFueSBMdGQxEzARBgNVBAMM" +
                    "CmFydHNhcG9sbG8xJTAjBgkqhkiG9w0BCQEWFmxlbWVzaGtvYXRAbWVnYWJhbmsu" +
                    "dWEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDR7qdNU5/idfgxVVRD" +
                    "gOxdFsuIuMsFhB88X4z8Q0730BGTEWvAyhU7EqyY/JVPXzSipOxBut0zcqRov+YS" +
                    "YRVDEeRUIgzYM3QnLk/FrJRDFARIvaSYLT9HTNb+64fcUj4mXElGgi+g5D0JE6aG" +
                    "08k8NVoifHWCB/SOjYvb8H+XS7otrAUqotQvoYUpIP7E+Mv6pKUbluh1ksZ1MuhP" +
                    "l5mMUq5MKVTkUiGjDIv8ccNUCMhl8nn05D1uGH2ViGa5n3TXxJ8T/ni57DBL36kE" +
                    "nC4nANdQKK5vt+iLLlUEvArVTziTwUYYD/UfA3bJCTF8S9SMhHs/fXQorVogQCJr" +
                    "CUNRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACrN80yMITg1oZvsulKUjFOYCfqS" +
                    "ivTvjhHJEPMhElCbTc+l7Noqz6ex5OgoWnFoOPA/R6tyrYxeBxthDmDFNmUYDcWW" +
                    "OBBj/SLP9BgxazpRLRzUDkRf2otIxdt6JHXSXOsvHazjC29IQZEIn6TUpqKSglIk" +
                    "RdhQMNHQXl94gP6zT7tVtFb5ir/12iG+W8q9I1Cj7tZL6knAFBbN8eGBbOWaod45" +
                    "0OuC9bnSrwyGIROajTEFU8/XCc3Yv8Ctwrn6TF5p7qR92ObJ+OFEPqfqwQ0aScxi" +
                    "qFrhV6vTMa8f+eWqfEYyVmUyuiyBb2DQFtO4n/TK/hJQO1y5hddWcJ1o9rI=" +
                    "-----END CERTIFICATE-----";
    public final static String MGB_PRIVATE_ENC_KEY =
            "-----BEGIN PRIVATE KEY-----" +
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Lg7rY95R4WfM" +
                    "wb5+X7oC94bCKazQv1jtqL7KVRS7aXvzsfKzUc+aqVSFY6S6U07tP6rEv9/ZFXv7" +
                    "YJ5ONVU2F5Oic30EzPnhWRW3ivjlzC3gLUjhD6MiWzOZ0WyykVTowUR2smxpLJbR" +
                    "iokj9GQPf0WTvULqyhEu+stZhWF2RYNsJPzDlY8Q3ujISKmqCruBmJKV8NeQ2PCR" +
                    "UQd6fe6RQGwbaVO2heisMzknRVXegYJY39FhNkzQHao0m1c352E3b5ChRQwxiSX7" +
                    "6zN8N79n9XGbPm0thi548yMNIqnY9NR+sXrYYDNJvntQYIWM5XwwrNP8G3/LfAcd" +
                    "OpaAmf1RAgMBAAECggEBALRfs/zdpjWdUtubsCgzsxp80R1175TRb67Ft+Vei7X1" +
                    "9n5l8o0ev0I4/rvzw5/R+/LgMX2bsOiOrYUWHDcdadnQanJXfBgONpYTtLvEbglz" +
                    "8pleyiYnXXsUC+ukRmzlY79PztvbIGFRmJygNXuyXGIasT+nWD7NLjXpc9/2im7e" +
                    "8mwdgGcDGaqJHiCwTPVsrqhw/wtGwFi+J2n2S6PhuoZmg80efBiLWxNOEhDGTwa2" +
                    "dbFuXEB3j6tLn+DyEdVNog0P8wusDzDamHC5i4PE/n8ZHYIkFSnttcClwCObFP0G" +
                    "MbfMO+sJ1JklRzATp36HnHHjvL0tidearQwItwggGAECgYEA7bxOODmHHKlSdxx8" +
                    "JLPIE6wilWhjYg1TBsVPVTRZSiWhmq5WHuB3PzjiV3CkG09YmsJaL4aYKa29MRzL" +
                    "uHjSpyE0/lwro4U7VK7VMU8oqGPwLQVeXbh+e8Uh1tDDk60NhWI89RCWiBKFFi/P" +
                    "Suxv+bxNg03gbdle+km1ue2S8MECgYEAyY9xaOsJT/NURl8ado5/ikMvR8VYCMpk" +
                    "1++0IwDgyJw6C5BllBEexbvSYUjK2gwgMBMYtKSd3G2fUKTgPJRLIv+1A3KPTL+P" +
                    "MlarMAAggMX4S0K607UQplAuuLqBgdm3Zpj/ZkVUCQk3boaqYRH6rIhlcyHg24ac" +
                    "P7hcZwynoJECgYAuyKzX8bI+GLAq0oc3rc2E2Y4gut8774VUQsX+7YNYzRkFWKOI" +
                    "BgJRhb89F+SjnzS/l9mpmqIdKZyeqp0Im3ZQ/37vQ3IvBswLOTCpOHu2z5v3MCRG" +
                    "60Sw1LV5EbI7QIX1psR6MZ59/q8EE7qGcwsCKWVTnqK421sOhCzn/vG4wQKBgFr5" +
                    "T2rXiuB3J3aLvln8fzxcjp6KR+3PzCxamKej4dEqEljd17s47va4i4A1Zrl795s7" +
                    "Q09lbYrsP5gakstE85TcbUsdDejKHUvPKn0D0afNsv/lIoYjl1w5nJzsMT/2kHzS" +
                    "WZRDfmaFrmtIhOZDQy1UctXAWMk8vJFWGP66C37BAoGAdbsfpM3zF3ca3GeaYucr" +
                    "d1OnRPoORLgD2+AJ2I/yIg9l6+bCDFyl4XmIW5M/sDmsLEnYUXu2VFcEYavrQ/K4" +
                    "ecdkDKaSwVuM07hPsr42uiW1usUdqAqT7hEqrzNsmdu+okiKml0brb6rJW0FObO+" +
                    "IXphifgUyvSvrQg9URuzYEI=" +
                    "-----END PRIVATE KEY-----";

    public final static String MGB_PUBLIC_DEC_KEY =
            "-----BEGIN CERTIFICATE-----" +
                    "MIIDZjCCAk4CCQCUpPLSmyfeSDANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJ1" +
                    "azENMAsGA1UECAwEa3lpdjENMAsGA1UEBwwEa3lpdjEMMAoGA1UECgwDbWdiMRMw" +
                    "EQYDVQQDDAphcnRzYXBvbGxvMSUwIwYJKoZIhvcNAQkBFhZsZW1lc2hrb2F0QG1l" +
                    "Z2FiYW5rLnVhMB4XDTIxMDIxMTE0NTgzMVoXDTIxMDMxMzE0NTgzMVowdTELMAkG" +
                    "A1UEBhMCdWsxDTALBgNVBAgMBGt5aXYxDTALBgNVBAcMBGt5aXYxDDAKBgNVBAoM" +
                    "A21nYjETMBEGA1UEAwwKYXJ0c2Fwb2xsbzElMCMGCSqGSIb3DQEJARYWbGVtZXNo" +
                    "a29hdEBtZWdhYmFuay51YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB" +
                    "ALsuDutj3lHhZ8zBvn5fugL3hsIprNC/WO2ovspVFLtpe/Ox8rNRz5qpVIVjpLpT" +
                    "Tu0/qsS/39kVe/tgnk41VTYXk6JzfQTM+eFZFbeK+OXMLeAtSOEPoyJbM5nRbLKR" +
                    "VOjBRHaybGksltGKiSP0ZA9/RZO9QurKES76y1mFYXZFg2wk/MOVjxDe6MhIqaoK" +
                    "u4GYkpXw15DY8JFRB3p97pFAbBtpU7aF6KwzOSdFVd6Bgljf0WE2TNAdqjSbVzfn" +
                    "YTdvkKFFDDGJJfvrM3w3v2f1cZs+bS2GLnjzIw0iqdj01H6xethgM0m+e1BghYzl" +
                    "fDCs0/wbf8t8Bx06loCZ/VECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEADiBYZMie" +
                    "wejMZEp63voNOCdsp06WPNngBjqwL4YadPledOctDIsVON39gCogfbnJLi0Xm5j0" +
                    "mE4b2WMjL4DZfmaPz5iSKzvC9QUj9DbAQGBESgLor/zgoQEZC6L2zaoY6eBrNthu" +
                    "TjF+9uBEiTfWfxJjFQ7s0kMMZa9m6ApCEvJ9A9ScfijcCSEgojwQaltnq0mfziEe" +
                    "5WM2zOGrmAca8Sj6f16QRMQbbB3hpcWaONO57JzjfZ9FkI1o8N4YcSp7hMqSPWYX" +
                    "DmFTr3xK+QtkeT8oBpAT9UtZIPdXKVMUF5LhblLkjdfcK4vBxWWsfVIs7pzFKrzh" +
                    "OaQxM570D8B6Mg==-----END CERTIFICATE-----";
    public final static String MGB_PRIVATE_DEC_KEY =
            "-----BEGIN PRIVATE KEY-----" +
                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDR7qdNU5/idfgx" +
                    "VVRDgOxdFsuIuMsFhB88X4z8Q0730BGTEWvAyhU7EqyY/JVPXzSipOxBut0zcqRo" +
                    "v+YSYRVDEeRUIgzYM3QnLk/FrJRDFARIvaSYLT9HTNb+64fcUj4mXElGgi+g5D0J" +
                    "E6aG08k8NVoifHWCB/SOjYvb8H+XS7otrAUqotQvoYUpIP7E+Mv6pKUbluh1ksZ1" +
                    "MuhPl5mMUq5MKVTkUiGjDIv8ccNUCMhl8nn05D1uGH2ViGa5n3TXxJ8T/ni57DBL" +
                    "36kEnC4nANdQKK5vt+iLLlUEvArVTziTwUYYD/UfA3bJCTF8S9SMhHs/fXQorVog" +
                    "QCJrCUNRAgMBAAECggEAEZX+adnhgOUE/4z4XBdGtZ2dOzzPtQyWWUZf1xoEWXoS" +
                    "ntFMx3+mO6aa0s4F6/o7vIw4RmFS+mZWI3g/27ZKQ64SBII9tTbKOiYFBLgqS1w3" +
                    "56gLS7wumthzAjPU074H+sqsUL3DI6U6/7Gnt4+yQdruTAlFBrmH4RE2cBw7c/77" +
                    "G8jdLu8bmeZy2UInB5w+c1MbzQOpntEhi+8n2hMrvZ8MK9lt9mAtJRXH2DgUfu6S" +
                    "99k3maybp8YCi0Offrn0Mb6tTuN5It+K5E4scJMwqQKJ46Ncmmy7T2FEaG1p9f+v" +
                    "geEsrjxD/i/a8WBH943YJmbOVFE+h7WHuMcSI9QKgQKBgQDz4gwWYZjTw4acnQDq" +
                    "I9Md7bTV8htr6U8AYpfBe/g9/aF6R2YSECv+CRM9Oi4asquU2sAXJTFqGjOnHANS" +
                    "rCLvF0faBKBOgucQg97Cjsv42CD7KjFhWS38b+ZdfzbHZKpCeb2urC8X0AF906gm" +
                    "WD4+s/00AkTBF0+ltMI2gvacmQKBgQDcXMkzttb2lTsMX4AIPKVxo0sPCiv/vjei" +
                    "BkNPbks+y9WVntj/4HPwzxbT71AHbdWa8yxxaWHQO3mqrRXIftLWt06mZciqzhIB" +
                    "SsxcHrmsw/QmGHpqAj0uaNjPbw2Xlp4tJURJw1AFM/ggoUtYLoHNOydHd2+XI3Ss" +
                    "YphdXNOXeQKBgDUJN2+2kbGbl65/Ri+k0shzZRwRpnz1I8UFq9LbzsRMX81jsYLE" +
                    "GY0JFDIAcP5FVKLuX0+pOvHD+O+iW+aioIY2Hd3/m4z3UqB4zPyqaRkYhzOXnV16" +
                    "M1HuU76JZ7Q84/nI18Mglq0rAugGG08baY3hPnMM+z6yfxOeF44bNN4hAoGBAKLv" +
                    "kG3GgcetrA2IB5kPjp0pynQCZ2of8e7Bhr+So9x4xyJsY7M++TtTRGPMjXYQxmJd" +
                    "77yj2QkpENscRAENlUPiIitzEx8IY9PExLpQlaWi9kG807bSlP5d1AH88SXm3mov" +
                    "JgEMg3x1YsBtwtIfAScI2BBFxaMROlHETTirTGCxAoGBAJ82Q2emyWyVUnttjHTv" +
                    "HZSDdjpaYLGd9JpnIy0wPcepv4EtVkwmymv9uc8HN56EBry/9s4e6OzyXoXts3/i" +
                    "LVTM1qV/4YhDaVqIDBPH0c6LqqXQrI3V5rIhuW6lgPspoEUgRqYj7voV+5CgNTtQ" +
                    "uExXn/GuD8+QoduvLhptlSiN-----END PRIVATE KEY-----";

    public final static String M_ENCODED_TEXT = "eyJraWQiOiJBcnRzYXBvbGxvIiwiYWxnIjoiUlMyNTYifQ.ZXlKbGJtTWlPaUpCTWpVMlIwTk5JaXdpWVd4bklqb2lVbE5CTFU5QlJWQXRNalUySW4wLmkzVUFscXFKZk9nSjJPekV5cFlyeTFBUzV5QUJnTDZLTmtDNUNrM2drTWdVN08yaU1EOU1PUXg3VGtHM0RLckdpY0UtalV0TFJOQWNiOWFrZ1hXMlFBTTZwMWcwaW9acEIwaFRveTdBWFRPTFVDamdFMkhUWFNtNWRjcHl1ajZ3clRqUkxkVXBtX0tuWXpEbGNXTXhBbDlNVGZDekNETTI4cVpsVGpDNHdablhZX1NWcUZ3b3NTYzZQNE8wYzBRUzZDVUtCNTZxMVV1YVl3QVJqaldUcW41OVl5NXU2aWU4cXR3clpacmdBWVBZa2RBS2RQNXh2aWZHa1FzM3o0UXRBXzdRWS10R19hcTBsa3FiUFQySHVNa01wTExMT25TTTNhenJ4RUplclNtSHF6TWRKaVRTekQyWFg4UGtZQ1NfSldtZVZzNUtNN0lFUXRtUUlzaEViQS5uLTY5Y1hVRU15MHBtRkY2LlR1SDc1czFmUGxMNWZPeDFnNW5XNjJOU1VKcnJXS0NYcXR1WFM5OHZndFJPU0R1V3ZRV3JxcDFheDhyVnB5YXprWEZVUWFNS0NuVzFheHpmWGRxVkxGMjc3NFVVQTEyb1NlYWwtUW5Hb0ZRZTRSMF9naWowX2FJZEdoaUQyQm1DckN6Z0h1UEtDVmFTX3hZSm1qanNIS2RLX1A5Q280VUE0cXlfY0xEdVhxcWkxWGR6U1dlMGdRcVZnN2tUNG5CTVJtZjBNUXVPTU9TNjQ4akNJbjBnQ21RU2xKRUo2TXI3U0RqYnJLTG5BZU82Q3cyc3hCMldqaFZlUE9RUlJoOW5ta2xrUEEyams5enpiY2NWTDJMVW03bHNpamhNUGkxX1gxZmJURHlpSmtWUzZHLTZGT1YxSzhCdnRXaFFGQ0hKaEppZTJuVGZpLXU1Ymg5dWZtNjlHelAxeXBidTRmZWlNVEplempqOF9vUUIzcnY2WktDbXA3RmU0cWNIZnFmTXJXTU5hLXBrV203c2lsMGx5LXdBdDZFUlByMjhzNHNIcl9odWg0SHQ0M0MwdnBCM3Zpdl9WSWlZWUFxLXpCbnk0S1kuU09odGRaeEdMZ2dlSE1IT0hJNEhBZw.NOlb_FSdUG7zib5IEu8kbwvlETPzL8N9mNKCpJ9MeCTt3kYJ1VOeYEfo8F456S4w63K4Wtz1nqFPDOA9cAFRJAbISxWRCacrrHL2NBt1IOjV2Vtj0SodNAyvnV-HmNvFp2nDVGdXVh7sCN7LVx04glWWfaXzxlJLdtHht6IAc8er7zKJdK-SVqdTU7MIDEUxU88UUKqw0ct0IUdjnxlVd9rE0gtyHmLshNF0M9Nr6W-HEdOOTCQAALoSOVu0ARW6CwETnBZQEJfqhG-04F8KIeMnEW0uxtygnSu1gMHvD60JXzR6dRuo-nbkVNF05kykT_yU-IF-UKFqY2Wlnlqhaw";





    public final static String Y_PUBLIC_KEY = "-----BEGIN CERTIFICATE-----" +
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
    public final static String Y_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----" +
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

    public final static String Y_ENCODED_TEXT = "eyJraWQiOiJ5cHlseXBlbiIsImN0eSI6IkpXRSIsInR5cCI6IkpPU0UiLCJhbGciOiJQUzI1NiJ9.ZXlKMGVYQWlPaUpLVDFORklpd2laVzVqSWpvaVFUSTFOa2REVFNJc0ltbGhkQ0k2TVRVMk16STJOVGN3TkN3aVlXeG5Jam9pVWxOQkxVOUJSVkF0TWpVMklpd2lhMmxrSWpvaVdVOVZVbDlLVjBWZlMwVlpYMGxFSW4wLlF1dmQ1aG5DOFkxdjlmejdjRUlwWHNYZWRjd09QSm5rQzcwVUdNbzVES214ZDM3cTlrYzFZdFY1eG5VUTgzNnRoSEVneG5xUkNqRWJiTmdRUERYQUo5bHUzWlZEdHRhZzZfVTNyT2FnVEpMcTd6Skp3aFZ0b2cxN3NWcjlrWFdhMVJzeTJjdTZzM1dEUE1yNVdYbG9zOUZxNkk2R1dfOVdNWk96RkZ3bXZmaHMyLTJzNmlzWmg3SF9rdlhWYWtBUldmYjB0UzBhN25pQXdDd0tGWkh1RHB3NmJuWlQtZmd1ZWw3T3NOMHBTRVh5cTFhREZmeDlOb25KYWdiV3dvdUIxTFFNYlE5SGhmYmswUWUtZTZvYU8xMm43THRDNmF0eGVKX0locnNPc2xHTGl6TXk5eXJOeE56QUsxR0pqX0RsWlpTM0R1MkMxTUNkOG55N3haYmxhUS54SW9ZWG1FcU54aXdfX3FULlJUaWVxdkZYSGZ1ZThmaHZkV2VwQkwzdWwtWkgxR2ZFMlB6eTBwdkYyYkdnSzg4NGh0UzVwYlVaSVQ0OGhpdUdOYVdMSjNkaUdnT2dCOUJ0QWNKWFZXTDMySXJkV2tLYWJENUM1VGFpWGZYbUlOaEZ6dHVoMDVJc3VXUExWdkFQNWlYTTN4TnVfTlRFVW9uUDEwbVBzRmZhVDJTck8tQXRtOUl6MkFXbVVxS0xOc3A2QXo0UVctNFlVUXBlSkJ1b3lrcUQ1R1Zlc1BsRWREYnk3dzdhaXZ2eDlaMG5BdzBhTS1mZnAtMUx2My1DdTkwRTl4Zm5oOEdYTFRFN1QtaVZQRU5FRmktRDFiSDhuWjFhT21UNFRrUjNhbW9GRURGZUR4MkNaQzRoLXVFLUdjNTVKWWFoQVU5clFiaHZFUG5MUk5LbjBXN0RtTUhhZV9ETU45RkhaeTZGSnlUR0oyQUdpeEJXUFJ0VE5qRC1iVl9uUHVKeEVyYzZtV25vbWtwQnJIRlVOZ0ZWRjhjanpuTGhTT2ZnOWFoRlBJN0IxTXVoMkZJdXJtRUdTaGJyMmV5cVJROVo4N1Q2QWpVdXJhbDVsY2M3REZLUHd2dkdlaEtpbGo1NF9Yei05X2JRbkdTclJDRWgyZVhlcFBmaFBRU3pNcGsya3UxRVl2YmplLXlqbkxRYW9NQ3I1bUM3RGhHejdoWkN5ZVowdm1ldlFJdFpEUnZ6S2NTRDJBeXp2OFBGNi0xYlBVNzJhNFVOYUFzaEd4S0NZYnpHdGY2dUJLdXd0ell4b1NCb2phSEIyUkU1aWJBT3UzWld0N0dXem41NHU2TmF2SENTMEpWVUh5Wi1yTGlwYXZLeGFkeWtkTy00RzhVNEVrOHNYLWJGbFNESW1UbnVkdGUyTXZwVjdiR1RkQU1sUHh5SUFnbDNORzdPMHA0TmN1emhPRnVRbmRsVUFmWVBqanlfMDRySEhWcXdadzB0Sl9mbkUyUG1NcHhHQnlMNU5UOWt6QkNmY1pvZUkyLVpGLVkxcEluaHFOYW1vRzdlNGY4eDNBRXZkZVVJU0gwYzVLMWt0enhqME9kakNTSFBnTm9IMkVDU0xLVVBteHVIcmR4cUN2RGxxRkFFVy1DdzZEd1BoTUNlR3JnWFlic0h4ald2TlJSNXRibFkyaHJfd0o3ODZ3V1A1RXpUZS1QRmZuaTAwMlQybUxwZmdmVVpySS1ubGlLa2dPaGxndi14dk53TjhXaEItTHVTQVpQSmdqM0ZRTFllcHA5UFNIc0thQUdnU3RhMk1DQXZ5dHJkeFZPUmR5UXNRWWJWQXJGQlZsc1BpTFBEeUk4OWlYNDBUVjdlcUt2VjhSNDdRdHdreHZFaGRZTUVLVGNzUU9JRGFRLTZVVkx0RkhldWdTdWdraWxMRGRsdmRhdkFlVDMwVlVOY2dvX1N4ekVUOUwxYjdoUUw3YjZiQ2g3ZVB5akxUQ1lMT1RDLWkzdmdiWmc4Qkx5TXhaaU8yc29LT2RrNlJEV0hjdUZxZU5TWHFDZ2pxR0hDQzFIN0dUYlQ0YVBvQUZBRE45TnBveThLTGFQX1hkMk04ZEMyQmh3S1NGRTlmRU8teWM4TFJMTW0wOUFtVTQ3Nm1odldCdWFkM0pvakwwRXRuZ0xpTXl0QTlRRjczVEowMm4zTUtWWm9BLWVXUmtJWWcxcmNTclVDM2YzR0dDTnNheEhzTnoybkpZeTZqNUxDUFMtVWxtVTFzUkFNbHJVbWxPMEZRbERJaWY5M3RLYkhhc1Vtb1BxbENoTnJfcHVkcGQ1NnMzTWJGLXFMR2ZYSHVXcHFpSTl5OWVYY2dxdXFIaGRkMlViQ2JJd3hrdy5jWDhtSEFRN19Pb2tBWGthRHYtRnB3.prnxd9W_l9-Ql5KyWIz3q7O_h-sNPuc6jYQdFdg5F6Lu92x9hzjcXlBuQJxxkiwFvnKaeFjiXm818ZXutooCjbAPx0deaFHHJ6OPEe_yTU5pF147jdPxAieTX4XKWGriVmP5VCbrGJg1u7itTqZ8JAiqAjcR4JNO0k6eHFLMp2253974OrhA7XET4QJfVU6SAAzWB7rOSsPp74QSwxWakjNU0RbfCcoJBVMkM0ipc4RxXPsFQ6ZBpiR6zOVVItLG8bTvr0ISvm85k1I9o254acDOMXTtZyv28qG8IfCp8kNGiwM7BdM3MKl8yEm1xB448qAug-3t6mfFU3JFIRQzOg";

}
