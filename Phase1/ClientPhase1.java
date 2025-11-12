// Imports pour le réseau (IO = Input/Output)
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

// Imports pour la cryptographie
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Imports pour l'encodage et autres utilitaires
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom; // Bien que nous n'en ayons pas besoin ici, c'est bon à savoir

public class ClientPhase1 {

    public static void main(String[] args) {
        // Le serveur est sur notre machine ("localhost") et écoute sur le port 8888 
        String host = "localhost";
        int port = 8888;

        System.out.println("--- Démarrage du Client ---");

        // Nous mettons tout dans un "try-with-resources"
        // Cela garantit que la socket et les flux seront fermés automatiquement
        try (
            Socket socket = new Socket(host, port);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
        ) {

            System.out.println("Connecté au serveur sur " + host + ":" + port);

            // -----------------------------------------------------------------
            // ÉTAPE 2 : LOGIQUE DU TEST 1 (3DES) 
            // -----------------------------------------------------------------
        System.out.println("\n--- DÉBUT TEST 1 : 3DES/ECB ---");

            // 1. Recevoir le "Welcome Message" 
            String welcome = in.readLine();
            System.out.println("Serveur : " + welcome);

            // 2. Générer une clé 3DES 
            System.out.println("Client : Génération de la clé 3DES...");
            KeyGenerator keyGen3DES = KeyGenerator.getInstance("DESede");
            SecretKey cle3DES = keyGen3DES.generateKey();

            // 3. Envoyer la clé en Base64 
            String cle3DES_Base64 = Base64.getEncoder().encodeToString(cle3DES.getEncoded());
            out.println(cle3DES_Base64);
            System.out.println("Client : Clé 3DES envoyée (Base64).");

            // 4. Recevoir le message aléatoire 
            String messageClair = in.readLine();
            System.out.println("Serveur : Message à chiffrer reçu.");

            // 5. Chiffrer le message reçu 
            System.out.println("Client : Chiffrement du message avec 3DES/ECB/PKCS5Padding...");
            Cipher cipher3DES = Cipher.getInstance("DESede/ECB/PKCS5Padding"); // 
            cipher3DES.init(Cipher.ENCRYPT_MODE, cle3DES);
            byte[] messageChiffreBytes = cipher3DES.doFinal(messageClair.getBytes(StandardCharsets.UTF_8));

            // 6. Envoyer le texte chiffré en Base64 
            String messageChiffreBase64 = Base64.getEncoder().encodeToString(messageChiffreBytes);
            out.println(messageChiffreBase64);
            System.out.println("Client : Message chiffré envoyé.");

            // 7. Recevoir la confirmation (OK/KO) 
            String reponseTest1 = in.readLine();
            System.out.println("Serveur : Résultat Test 1 = " + reponseTest1);

            if (!reponseTest1.contains("OK")) {
                System.err.println("Le Test 1 a échoué. Arrêt.");
                return; // Quitte le programme
            }
            // -----------------------------------------------------------------
            // ÉTAPE 3 : LOGIQUE DU TEST 2 (AES/GCM) 
            // -----------------------------------------------------------------
            System.out.println("\n--- DÉBUT TEST 2 : AES/GCM ---");
            
            // 1. Recevoir la clé AES en Base64 
            String cleAES_Base64 = in.readLine();
            System.out.println("Serveur : Clé AES reçue.");
            byte[] cleAESBytes = Base64.getDecoder().decode(cleAES_Base64);
            // On reconstruit la clé à partir des octets
            SecretKey cleAES = new SecretKeySpec(cleAESBytes, "AES");

            // 2. Recevoir l'IV en Base64 
            String iv_Base64 = in.readLine();
            System.out.println("Serveur : IV reçu.");
            byte[] ivBytes = Base64.getDecoder().decode(iv_Base64);

            // 3. Recevoir l'AAD (String) 
            String aad = in.readLine();
            System.out.println("Serveur : AAD reçu.");
            byte[] aadBytes = aad.getBytes(StandardCharsets.UTF_8);
            
            // 4. Recevoir le texte chiffré en Base64 
            String texteChiffreAES_Base64 = in.readLine();
            System.out.println("Serveur : Message chiffré AES reçu.");
            byte[] texteChiffreAESBytes = Base64.getDecoder().decode(texteChiffreAES_Base64);

            // 5. Déchiffrer le message 
            System.out.println("Client : Déchiffrement du message avec AES/GCM/NoPadding...");
            Cipher cipherAES = Cipher.getInstance("AES/GCM/NoPadding"); // 
            
            // On crée les paramètres GCM : taille du tag (128 bits) et l'IV
            // L'analyse du .jar montre que l'IV fait 12 bytes, 
            // ce qui est parfait.
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, ivBytes);
            
            cipherAES.init(Cipher.DECRYPT_MODE, cleAES, gcmParamSpec);
            
            // ÉTAPE IMPORTANTE : Fournir l'AAD AVANT de déchiffrer
            cipherAES.updateAAD(aadBytes); 
            
            // Déchiffrer le message
            byte[] messageDechiffreBytes = cipherAES.doFinal(texteChiffreAESBytes);
            
            // 6. Envoyer le message déchiffré en clair 
            String messageDechiffreClair = new String(messageDechiffreBytes, StandardCharsets.UTF_8);
            out.println(messageDechiffreClair);
            System.out.println("Client : Message déchiffré envoyé.");

            // 7. Recevoir la confirmation finale (OK/KO) 
            String reponseTest2 = in.readLine();
            System.out.println("Serveur : Résultat Test 2 = " + reponseTest2);

            System.out.println("--- Fin des opérations. Client terminé. ---");

        } catch (Exception e) {
            // S'il y a une erreur (serveur pas allumé, erreur de crypto...), 
            // nous l'affichons
            System.err.println("Une erreur est survenue :");
            e.printStackTrace();
        }
    }
}