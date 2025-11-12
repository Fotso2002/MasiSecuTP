import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws IOException {
        // Configuration du serveur
        String host = "127.0.0.1";
        int port = 8888;
        System.out.println("Connexion à " + host + ":" + port);
        try (
            Socket socket = new Socket(host, port);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
        ){
            // Phase 1 : 3DES
            KeyGenerator desKeyGen = KeyGenerator.getInstance("DESede");
            desKeyGen.init(168, new SecureRandom());
            SecretKey desSessionKey = desKeyGen.generateKey();
            Base64.Encoder encoder = Base64.getEncoder();
            String session = encoder.encodeToString(desSessionKey.getEncoded());

            System.out.println(reader.readLine());
            System.out.println("Envoi de la clé 3DES au serveur...");
            writer.println(session);
            writer.flush();
            System.out.println("Clé 3DES encodée envoyée : " + session);


            String messageToEncrypt = reader.readLine();
            System.out.println("Message reçu à chiffrer : " + messageToEncrypt);

            Cipher desCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            desCipher.init(Cipher.ENCRYPT_MODE, desSessionKey);
            byte[] encryptedDes = desCipher.doFinal(messageToEncrypt.getBytes());
            String encryptedDesBase64 = Base64.getEncoder().encodeToString(encryptedDes);

            System.out.println("Envoi du message chiffré (3DES)...");
            writer.println(encryptedDesBase64);
            writer.flush();

            // Phase 2 : AES/GCM
            String aesKeyBase64 = reader.readLine();
            String ivBase64 = reader.readLine();
            String aad = reader.readLine();
            String cipherTextBase64 = reader.readLine();

            byte[] aesKeyBytes = Base64.getDecoder().decode(aesKeyBase64);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            byte[] ivBytes = Base64.getDecoder().decode(ivBase64);
            byte[] cipherTextBytes = Base64.getDecoder().decode(cipherTextBase64);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
            Cipher dechiffrement = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
            dechiffrement.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            dechiffrement.updateAAD(aad.getBytes(StandardCharsets.UTF_8));

            byte[] decryptedBytes = dechiffrement.doFinal(cipherTextBytes);
            String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

            System.out.println("Message déchiffré (AES/GCM) : " + decryptedText);
            writer.println(decryptedText);
            writer.flush();

        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }
}