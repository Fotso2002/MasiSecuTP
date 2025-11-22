package server_acs;

import common.NetworkUtils;
import javax.net.ssl.*;
import java.io.*;

public class ACSMain {
    private static final int PORT = 9090; 
    
    public static void main(String[] args) {
        try {
            System.out.println("Démarrage du Serveur ACS (Banque Client)...");
            
            // On charge l'identité ACS et le Truststore
            SSLContext ctx = NetworkUtils.createSSLContext(
                "keystores/acs.jks", "password",
                "keystores/truststore.jks", "password"
            );

            SSLServerSocketFactory factory = ctx.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT);
            
            System.out.println("ACS écoute sur le port " + PORT + " (SSL)");

            while(true) {
                // Accepte une connexion entrante
                try (SSLSocket socket = (SSLSocket) serverSocket.accept();
                     BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                     PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
                    
                    String message = in.readLine();
                    System.out.println("Reçu : " + message);
                    
                    // Réponse simple
                    out.println("ACK from ACS");
                } catch(Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}