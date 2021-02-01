import rsaEncodeDecode.EncDec;

public class Main {

    public static void encryptDecrypt(String plainText) {
        EncDec encDec = new EncDec();

        System.out.println("PlainText: " + plainText);
        System.out.println("PlainText size: " + plainText.length() + "\n");

        System.out.println("Encryption key length: " + encDec.getMEncryptionKeyLength());
        System.out.println("Encryption algorithm: " + encDec.getMEncryptionAlgo());
        System.out.println("Encryption transform: " + encDec.getMTransformation() + "\n");

        byte[] encryptedText = encDec.encryptText(plainText);
        System.out.println("Encrypted text: " + EncDec.keyToNumber(encryptedText).toString());
        System.out.println("Encrypted text length: " + EncDec.keyToNumber(encryptedText).toString().length() + "\n");

        System.out.println("Public key: " + EncDec.keyToNumber(encDec.getPrivateKeyAsByteArray()).toString());
        System.out.println("Public key length: " + EncDec.keyToNumber(encDec.getPrivateKeyAsByteArray()).toString().length());
        System.out.println("Private key: " + EncDec.keyToNumber(encDec.getPublicKeyAsByteArray()).toString());
        System.out.println("Private key length: " + EncDec.keyToNumber(encDec.getPublicKeyAsByteArray()).toString().length() + "\n");

        String decryptedText = new String(encDec.decryptText(encryptedText));
        System.out.println("Decrypted text: " + decryptedText);
        System.out.println("Decrypted text length: " + decryptedText.length());
    }

    public static void main(String[] args) {
        Main.encryptDecrypt("Hello World!");
    }
}
