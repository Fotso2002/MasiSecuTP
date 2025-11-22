package common;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtils {

    // Génère un "Sel" aléatoire (16 octets)
    public static String getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // Hache le mot de passe avec le sel en utilisant SHA-256
    public static String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // On mélange le mot de passe et le sel
            String input = password + salt;
            byte[] hashedBytes = md.digest(input.getBytes());
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Erreur de hachage", e);
        }
    }
}