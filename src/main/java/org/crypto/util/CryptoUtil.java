package org.crypto.util;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class CryptoUtil {
    private static final String AES = "AES";
    private static final String AES_CIPHER_ALGORITHM;
    static Scanner message;
    static final byte[] initializationVector;

    static{
        // We are using a Block cipher(CBC mode)
        AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";
        initializationVector = createInitializationVector();
    }

    // Function to create a
    // secret key
    public static SecretKey createAESKey() throws Exception {
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);
        keygenerator.init(256, securerandom);
        SecretKey key = keygenerator.generateKey();
        return key;
    }

    // Function to initialize a vector
    // with an arbitrary value
    public static byte[] createInitializationVector() {
        // Used with encryption
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    private static SecretKey getKeyFromText(String passcode)
    {
        String encodedKey=Base64.getEncoder().encodeToString(passcode.getBytes());
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        // rebuild key using SecretKeySpec
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
    // This function takes plaintext,the key with an initialization
    // vector to convert plainText into CipherText.
    public static byte[] do_AESEncryption(
            String plainText,
            String passcode) throws Exception {
        SecretKey secretKey = getKeyFromText(passcode);
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }

    // This function performs the reverse operation of the do_AESEncryption function.
    // It converts ciphertext to the plaintext using the key.
    public static String do_AESDecryption(
            byte[] cipherText,
            String passcode)
            throws Exception {
        SecretKey secretKey = getKeyFromText(passcode);
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }

    public static String encryptID(String key, String id) {
        String encryptedID = "";
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));

            encryptedID = Base64.getEncoder().encodeToString(cipher.doFinal(id.getBytes("UTF-8")));
        } catch (Exception e) {
            e.printStackTrace();
            encryptedID = "ERROR";
        }

        return encryptedID;
    }

    public static String decryptID(String key, String encryptedID) {

        String decryptedID = "";
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));

            byte[] decodedValue = cipher.doFinal(Base64.getDecoder().decode(encryptedID));
            decryptedID = new String(decodedValue);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedID;

    }
}
