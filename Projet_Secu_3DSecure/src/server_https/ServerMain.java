package server_https;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;

public class ServerMain {
    private static final int PORT = 8043;
    private static final String KEYSTORE_PATH = "keystores/server.jks";
    private static final String KEYSTORE_PASSWORD = "password"; // Mot de passe défini avec keytool

    public static void main(String[] args) {
        try {
            System.out.println("Démarrage du Serveur HTTPS sur le port " + PORT + "...");

            // 1. Charger le KeyStore (Notre certificat serveur)
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());

            // 2. Initialiser le gestionnaire de clés (KeyManager)
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // 3. Créer le contexte SSL
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);

            // 4. Créer la socket serveur SSL
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(PORT);

            System.out.println("Serveur prêt ! En attente de connexions...");

            while (true) {
                // Accepte une connexion et la confie à un thread (ClientHandler)
                new ClientHandler(serverSocket.accept()).start();
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Erreur critique : Impossible de démarrer le serveur.");
            System.err.println("Vérifiez que le fichier keystores/server.jks existe bien.");
        }
    }
}