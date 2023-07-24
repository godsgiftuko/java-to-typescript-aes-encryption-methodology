import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.simple.JSONObject;

class AES {
    // This method is used to encrypt a string with a given private key
    public static String encrypt(String strToEncrypt, String privateKey) {
        try {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(privateKey.toCharArray(), iv, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    // This method is used to decrypt a string with a given private key
    public static String decrypt(String strToDecrypt, String privateKey) {
        try {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(privateKey.toCharArray(), iv, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);

            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}

class Payload {
    JSONObject file;
    String names;
    int age;
    String flightNumber;
  
    public Payload(String names, int age, String flightNumber) {
        this.names = names;
        this.age = age;
        this.flightNumber = flightNumber;
    }

    public JSONObject getPayload() {
        JSONObject file = new JSONObject();
        file.put("names", this.names);
        file.put("age", this.age);
        file.put("flightNumber", this.flightNumber);
        return file;
    }
}

public class Main {
    public static void main(String[] args) {
        // Create a new instance of the Payload class
        Payload payload = new Payload("God'sgift Uko", 25, "ABC123");

        // Get the payload as a JSONObject
        JSONObject payloadJson = payload.getPayload();
        String payloadString = payloadJson.toJSONString();

        String privateKey = "my_super_secret_key_ho_ho_ho";

        // Call encryption method with the private key as a parameter
        String encryptedPayload = AES.encrypt(payloadString, privateKey);

        // Call decryption method with the private key as a parameter
        String decryptedPayload = AES.decrypt(encryptedPayload, privateKey);
      
      // Print the payload
        System.out.println(payloadString);
        System.out.println("Encrypted: " + encryptedPayload);
        System.out.println("Decrypted: " + decryptedPayload);
    }
}
