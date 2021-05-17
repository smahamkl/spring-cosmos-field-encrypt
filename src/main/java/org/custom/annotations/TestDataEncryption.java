package org.custom.annotations;

import com.github.nmorel.gwtjackson.client.exception.JsonSerializationException;

public class TestDataEncryption {

    public static void main(String[] args) throws JsonSerializationException, Exception
    {
//        Object object = new Object();
        ObjectToJsonConverter serializer = new ObjectToJsonConverter();
//        System.out.println(serializer.convertToJson(object));

        Person person = new Person("soufiane", "cheouati", "34");
        String jsonString = serializer.convertToJson(person);
        //assertEquals("{\"personAge\":\"34\",\"firstName\":\"Soufiane\",\"lastName\":\"Cheouati\"}", jsonString);
        System.out.println(jsonString);

        //------- Test Encryption/Decryption of the data -------------
//        String masterKey = "M@st3rPassw0rd!0";
//        String childKey1 = "Ch$ld1Passw0rd!1"; //W2QGq4+rJGu/zaOCxMhCOkqoL5AhQZD9BbPGC+q0k64=
//        String childKey2 = "Ch$ld2Passw0rd!2"; //Y28uXRFIx3H/jwOSa1sH9oYbD5Eyz/uoB9xopwU48+k=
//        // Encrypting the message using the symmetric key
//        byte[] cipherText = do_AESEncryption(childKey1, masterKey);
//        System.out.println("The ciphertext or Encrypted Message is: " + DatatypeConverter.printHexBinary(cipherText));
//        // Decrypting the encrypted message
//        String decryptedText = do_AESDecryption(cipherText, masterKey);
//        System.out.println("Original key: " + decryptedText);
//
//        String encrypId = CryptoUtil.encryptID(masterKey, childKey1);
//        System.out.println(encrypId);
//        System.out.println(CryptoUtil.decryptID(masterKey, encrypId));
//
//        encrypId = CryptoUtil.encryptID(masterKey, childKey2);
//        System.out.println(encrypId);
//        System.out.println(CryptoUtil.decryptID(masterKey, encrypId));
    }
}
