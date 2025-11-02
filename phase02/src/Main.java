import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(8888);
            System.out.println("Hello, this is the Server. Awaiting connection");
            Socket s = ss.accept();
            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
            s.setTcpNoDelay(true);

            pw.println("Hello, this is the Client. Awaiting connection");
            pw.flush();

            byte[] salt = Base64.getDecoder().decode(br.readLine().substring(5));
            byte[] iv = Base64.getDecoder().decode(br.readLine().substring(3));
            byte[] ct = Base64.getDecoder().decode(br.readLine().substring(3));

            SecretKey aesKey = deriveAesKey("laPassphrasePartagee", salt, 600000, 256);
            byte[] msg = decryptAesCbcPkcs5(aesKey, iv, ct);
            byte[] keyBytes = aesKey.getEncoded();
            byte[] suffix = "that's all folks".getBytes(StandardCharsets.UTF_8);
            MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
            sha3.update(keyBytes);
            sha3.update(msg);
            sha3.update(suffix);

            byte[] tagserveur = sha3.digest();
            pw.println("TAG:" + Base64.getEncoder().encodeToString(tagserveur));
            pw.flush();


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static SecretKey deriveAesKey(String pass, byte[] salt, int iters, int bits) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, iters, bits);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    private static byte[] decryptAesCbcPkcs5(SecretKey key, byte[] iv, byte[] plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(plaintext);
    }
}