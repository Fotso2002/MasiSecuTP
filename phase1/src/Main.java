import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;



public class Main {
    public static void main(String[] args) throws IOException {
        try {
            System.out.println("Hello world!");
            Socket socket = new Socket("127.0.0.1", 8888);
            Security.addProvider(new BouncyCastleProvider());
            BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
            //
            KeyGenerator cleGen = KeyGenerator.getInstance("DESede", "BC");
            cleGen.init(168, new SecureRandom());  // Utilisez une taille de clé appropriée pour Triple-DES (112 ou 168 bits)
            SecretKey cleSession = cleGen.generateKey();
            Base64.Encoder encoder = Base64.getEncoder();
            System.out.println("(DESede/ECB/PKCS5Padding) client: envoi de la cles de sesion");
            System.out.println("(DESede/ECB/PKCS5Padding) client: "+cleSession.toString());
            String session = encoder.encodeToString(cleSession.getEncoded());

            System.out.println(br.readLine());
            pw.println(session);
            pw.flush();

            //

            String response = br.readLine();
            System.out.println("(DESede/ECB/PKCS5Padding) client: message recu "+response);
            Cipher chiffrementE = Cipher.getInstance("DESede/ECB/PKCS5Padding", "BC");
            chiffrementE.init(Cipher.ENCRYPT_MODE,cleSession);
            byte[] messagecrypter= chiffrementE.doFinal(response.getBytes());
            System.out.println("(DESede/ECB/PKCS5Padding) client: message envoyer "+messagecrypter.toString());
            pw.println(Base64.getEncoder().encodeToString(messagecrypter));
            pw.flush();

            //
            String keyB64=br.readLine();
            String ivB64=br.readLine();
            String sAad=br.readLine();
            String ctB64=br.readLine();
            System.out.println(keyB64);
            System.out.println(ivB64);
            System.out.println(sAad);

            byte[] Bcle=Base64.getDecoder().decode(keyB64);
            SecretKey cle = new SecretKeySpec(Bcle, 0, Bcle.length, "AES");

            byte[] vecteurInit = Base64.getDecoder().decode(ivB64);

            byte[] texteCrypte=Base64.getDecoder().decode(ctB64);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, vecteurInit);
            String codeProvider;
            Cipher  dechiffrement= Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
            dechiffrement.init(Cipher.DECRYPT_MODE, cle, gcmSpec);
            dechiffrement.updateAAD(sAad.getBytes(StandardCharsets.UTF_8));

            byte[] texteClair = dechiffrement.doFinal(texteCrypte);

            String texteClairString = new String(texteClair, StandardCharsets.UTF_8);

            pw.println(texteClairString);

            pw.flush();
            System.out.println(texteClair);









        }catch (Exception e){
            e.printStackTrace();
        }
    }
}