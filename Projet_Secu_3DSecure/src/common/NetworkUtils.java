package common; // <--- TRES IMPORTANT : Doit être la première ligne

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;

public class NetworkUtils {
    
    // Charge une identité (Keystore) et une liste de confiance (Truststore) pour créer un contexte SSL
    public static SSLContext createSSLContext(String keystorePath, String keystorePass, String truststorePath, String truststorePass) throws Exception {
        
        // 1. Charger le KeyStore (Qui suis-je ?)
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, keystorePass.toCharArray());
        }

        // 2. Charger le TrustStore (En qui j'ai confiance ?)
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(truststorePath)) {
            trustStore.load(fis, truststorePass.toCharArray());
        }

        // 3. Initialiser les Managers
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keystorePass.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // 4. Créer le contexte SSL
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        
        return sslContext;
    }
}