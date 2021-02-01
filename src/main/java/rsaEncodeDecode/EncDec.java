package rsaEncodeDecode;

import lombok.Data;
import lombok.ToString;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Data
@ToString
public class EncDec {

    protected static String DEFAULT_ENCRYPTION_ALGORITHM = "RSA";
    protected static int DEFAULT_ENCRYPTION_KEY_LENGTH = 2048;
    protected static String DEFAULT_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    public String mEncryptionAlgo, mTransformation;
    public int mEncryptionKeyLength;
    public PublicKey mPublicKey;
    public PrivateKey mPrivateKey;

    public EncDec() {
        mEncryptionAlgo = EncDec.DEFAULT_ENCRYPTION_ALGORITHM;
        mEncryptionKeyLength = EncDec.DEFAULT_ENCRYPTION_KEY_LENGTH;
        mTransformation = EncDec.DEFAULT_TRANSFORMATION;
        mPublicKey = null;
        mPrivateKey = null;
    }

    public static BigInteger keyToNumber(byte[] byteArray) {
        return new BigInteger(1, byteArray);
    }

    public byte[] getPublicKeyAsByteArray() {
        return mPublicKey.getEncoded();
    }

    public byte[] getPrivateKeyAsByteArray() {
        return mPrivateKey.getEncoded();
    }

    public String getEncodedPublicKey() {
        return Base64.getEncoder().encodeToString(mPublicKey.getEncoded());
    }

    public String getEncodedPrivateKey() {
        return Base64.getEncoder().encodeToString(mPrivateKey.getEncoded());
    }

    public byte[] encryptText(String text) {
        byte[] encryptedText = null;

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(mEncryptionAlgo);
            kpg.initialize(mEncryptionKeyLength);

            KeyPair keyPair = kpg.generateKeyPair();

            mPublicKey = keyPair.getPublic();
            mPrivateKey = keyPair.getPrivate();

            Cipher cipher = Cipher.getInstance(mTransformation);
            cipher.init(Cipher.PUBLIC_KEY, mPublicKey);

            encryptedText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return encryptedText;
    }

    public byte[] decryptText(byte[] encryptedText) {
        byte[] decryptText = null;

        try {

            Cipher cipher = Cipher.getInstance(mTransformation);
            cipher.init(Cipher.PRIVATE_KEY, mPrivateKey);

            decryptText = cipher.doFinal(encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decryptText;
    }
}
