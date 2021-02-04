package util;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyUtils {
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

    public static RSAKey generateRsaKeys(String kid, KeyUse keyUse) {
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
}
