package server_acq;

import common.NetworkUtils;
import javax.net.ssl.*;
import java.io.*;

public class ACQMain {
    private static final int PORT_LISTEN = 9091; // Écoute le serveur HTTPS
    private static final String ACS_HOST = "localhost";
    private static final int ACS_PORT = 9090; // Parle à l'ACS

    public static void main(String[] args) {
        try {
            System.out.println("Démarrage du Serveur ACQ (Banque Site)...");

            // Identité : ACQ
            SSLContext ctx = NetworkUtils.createSSLContext(
                "keystores/acq.jks", "password",
                "keystores/truststore.jks", "password"
            );

            // Lance le serveur d'écoute dans un thread séparé
            new Thread(() -> startServer(ctx)).start();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Partie Serveur : Écoute HTTPS
    private static void startServer(SSLContext ctx) {
        try {
            SSLServerSocketFactory factory = ctx.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT_LISTEN);
            System.out.println("ACQ prêt sur le port " + PORT_LISTEN);

            while (true) {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept();
                     BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                     PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

                    String data = in.readLine();
                    System.out.println("Reçu du web : " + data);
                    
                    // Relais vers l'ACS
                    String responseFromACS = contactACS(ctx, data);
                    
                    // Renvoi de la réponse au web
                    out.println(responseFromACS);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Partie Client : Parle à l'ACS
    private static String contactACS(SSLContext ctx, String message) {
        try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(ACS_HOST, ACS_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            System.out.println("--> Envoi vers ACS...");
            out.println(message); // Envoi
            String response = in.readLine(); // Réception
            System.out.println("<-- Réponse ACS : " + response);
            return response;

        } catch (Exception e) {
            return "Erreur connexion ACS";
        }
    }
}