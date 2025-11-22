package server_https;

import java.util.HashMap;
import java.util.Map;
import common.CryptoUtils;

public class Database {
    // Stocke les infos : Login -> [Salt, HashedPassword]
    private static Map<String, String[]> users = new HashMap<>();

    // Initialisation avec un utilisateur de test
    static {
        String login = "admin";
        String password = "admin123"; // Mot de passe en clair (jamais stocké tel quel)
        
        String salt = CryptoUtils.getSalt();
        String hash = CryptoUtils.hashPassword(password, salt);
        
        users.put(login, new String[]{salt, hash});
        System.out.println("DB Init: Utilisateur 'admin' créé avec mot de passe 'admin123'");
    }

    public static boolean checkCredentials(String login, String passwordCandidate) {
        if (!users.containsKey(login)) {
            return false; // Utilisateur inconnu
        }

        String[] storedData = users.get(login);
        String storedSalt = storedData[0];
        String storedHash = storedData[1];

        // On re-hache le mot de passe reçu avec le sel stocké
        String candidateHash = CryptoUtils.hashPassword(passwordCandidate, storedSalt);

        // On compare le résultat avec le hash stocké
        return storedHash.equals(candidateHash);
    }
}