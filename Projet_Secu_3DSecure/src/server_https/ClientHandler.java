package server_https;

import common.NetworkUtils;
import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;

public class ClientHandler extends Thread {
    private Socket socket;
    
    // Configuration pour parler à l'ACQ
    private static final String ACQ_HOST = "localhost";
    private static final int ACQ_PORT = 9091;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            OutputStream out = socket.getOutputStream();
        ) {
            String line = in.readLine();
            if (line == null) return;
            System.out.println("Requête HTTPS : " + line);

            String[] parts = line.split(" ");
            String method = parts[0]; 
            
            // Récupérer la taille du contenu (pour POST)
            int contentLength = 0;
            String headerLine;
            while (!(headerLine = in.readLine()).isEmpty()) {
                if (headerLine.toLowerCase().startsWith("content-length:")) {
                    contentLength = Integer.parseInt(headerLine.split(":")[1].trim());
                }
            }

            if (method.equals("GET")) {
                sendLoginForm(out);
            } else if (method.equals("POST")) {
                char[] bodyChars = new char[contentLength];
                in.read(bodyChars, 0, contentLength);
                String body = new String(bodyChars);
                handleLogin(out, body);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendLoginForm(OutputStream out) throws IOException {
        String html = "<html><body style='font-family:sans-serif; text-align:center; padding-top:50px;'>" +
                "<h2>Bienvenue au Complexe de Vacances</h2>" +
                "<form method='POST' style='display:inline-block; text-align:left; border:1px solid #ccc; padding:20px;'>" +
                "Login: <input type='text' name='username' value='admin'><br><br>" +
                "Password: <input type='password' name='password' value='admin123'><br><br>" +
                "<input type='submit' value='Se connecter'>" +
                "</form>" +
                "</body></html>";
        sendHttpResponse(out, 200, html);
    }

    private void handleLogin(OutputStream out, String body) throws IOException {
        String[] pairs = body.split("&");
        String user = "", pass = "";

        for (String pair : pairs) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                if (kv[0].equals("username")) user = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                if (kv[0].equals("password")) pass = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            }
        }

        if (Database.checkCredentials(user, pass)) {
            System.out.println("Login OK. Tentative de connexion à l'ACQ...");
            
            // TEST PHASE 1 : On contacte l'ACQ pour vérifier le SSL
            String reponseACQ = testACQConnection();

            String paymentPage = "<html><body style='font-family:sans-serif; text-align:center;'>" +
                    "<h2 style='color:green'>Connexion reussie !</h2>" +
                    "<p>Test ACQ: <b>" + reponseACQ + "</b></p>" +
                    "<p>Veuillez proceder au paiement.</p>" +
                    "<button style='padding:10px 20px; font-size:16px;'>Paiement (Simulation)</button>" +
                    "</body></html>";
            sendHttpResponse(out, 200, paymentPage);
        } else {
            sendHttpResponse(out, 401, "<html><body><h1>Erreur: Identifiants incorrects</h1></body></html>");
        }
    }

    // Méthode pour tester la communication SSL avec l'ACQ
    private String testACQConnection() {
        try {
            // On charge l'identité SERVER et le Truststore
            SSLContext ctx = NetworkUtils.createSSLContext(
                "keystores/server.jks", "password", 
                "keystores/truststore.jks", "password"
            );
            
            try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(ACQ_HOST, ACQ_PORT);
                 PrintWriter outWriter = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader inReader = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                 
                // Envoi d'un message test
                outWriter.println("Test connexion HTTPS -> ACQ");
                
                // Lecture réponse
                return inReader.readLine();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "Erreur connexion ACQ: " + e.getMessage();
        }
    }

    private void sendHttpResponse(OutputStream out, int statusCode, String content) throws IOException {
        String status = (statusCode == 200) ? "200 OK" : "401 Unauthorized";
        String headers = "HTTP/1.1 " + status + "\r\n" +
                "Content-Type: text/html; charset=UTF-8\r\n" +
                "Content-Length: " + content.getBytes(StandardCharsets.UTF_8).length + "\r\n" +
                "\r\n";
        out.write(headers.getBytes(StandardCharsets.UTF_8));
        out.write(content.getBytes(StandardCharsets.UTF_8));
        out.flush();
    }
}