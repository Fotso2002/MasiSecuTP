import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.bouncycastle.math.ec.rfc8032.Ed25519.SIGNATURE_SIZE;

public class Main {
    private static final BigInteger G = BigInteger.valueOf(2L);
    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final SecureRandom RNG = new SecureRandom();
    private static String PASSPHRASE;
    static final int RSA_SIGNATURE_SIZE_BYTES = 256;
    public static void main(String[] args) {
        try {
            ServerSocket ss = new ServerSocket(8888);
            System.out.println("Hello, this is the Server. Awaiting connection");
            Socket s = ss.accept();
            BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
            s.setTcpNoDelay(true);

            BigInteger A =new BigInteger(1, Base64.getDecoder().decode(br.readLine().substring(2)));
            BigInteger b = randomExponent(256);
            BigInteger B = G.modPow(b, P);
            pw.println("B:" + b64enc(toFixedLen(B, 256)));
            pw.flush();
            BigInteger Z = A.modPow(b, P);
            byte[] zBytes = toFixedLen(Z, 256);
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(toFixedLen(G, 1));
            sha256.update(toFixedLen(P, 256));
            sha256.update(toFixedLen(A, 256));
            sha256.update(toFixedLen(B, 256));
            byte[] transcriptHash = sha256.digest();
            byte[] salt = "phase3 aead key ".getBytes();
            PASSPHRASE = b64enc(transcriptHash);
            SecretKey gcmKey = deriveAesKey(PASSPHRASE, salt, 600000, 256);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, RNG);
            KeyPair rsaSrv = kpg.generateKeyPair();
            byte[] rsaPubS_DER = rsaSrv.getPublic().getEncoded();
            byte[] blobS = gcmSeal(gcmKey, transcriptHash, rsaPubS_DER);
            pw.println("PUBS:" + b64enc(blobS));
            pw.flush();
            String pubcLine = br.readLine();
            byte[] blobC = b64dec(pubcLine.substring(5).trim());
            byte[] derC = gcmOpen(gcmKey, transcriptHash, blobC);
            PublicKey rsaPubC = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(derC));
            String message = br.readLine();
            Cipher oaepDec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            oaepDec.init(Cipher.DECRYPT_MODE, rsaSrv.getPrivate());


            byte[] ctM =oaepDec.doFinal(b64dec(message.substring(7).trim()));

            byte[] signature = signMessage(ctM, rsaSrv.getPrivate());

            byte[] sigPart1 = new byte[RSA_SIGNATURE_SIZE_BYTES / 2];
            byte[] sigPart2 = new byte[RSA_SIGNATURE_SIZE_BYTES / 2];
            System.arraycopy(signature, 0, sigPart1, 0, sigPart1.length);
            System.arraycopy(signature, sigPart1.length, sigPart2, 0, sigPart2.length);

            byte[] encryptedSig1 = encryptRsaOaep(sigPart1, rsaPubC);
            pw.println("SIG1:" + Base64.getEncoder().encodeToString(encryptedSig1));
            pw.flush();

            byte[] encryptedSig2 = encryptRsaOaep(sigPart2, rsaPubC);
            pw.println("SIG2:" + Base64.getEncoder().encodeToString(encryptedSig2));
            pw.flush();
            br.readLine();


        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.out.println("Hello world!");
    }
    private static SecretKey deriveAesKey(String pass, byte[] salt, int iters, int bits) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, iters, bits);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }
    private static byte[] toFixedLen(BigInteger x, int len) {
        byte[] t = x.toByteArray();
        if (t.length == len) {
            return t;
        } else {
            byte[] r;
            if (t[0] == 0 && t.length == len + 1) {
                r = new byte[len];
                System.arraycopy(t, 1, r, 0, len);
                return r;
            } else {
                r = new byte[len];
                System.arraycopy(t, Math.max(0, t.length - len), r, len - Math.min(len, t.length), Math.min(len, t.length));
                return r;
            }
        }
    }
    private static BigInteger randomExponent(int bits) {
        return (new BigInteger(bits, RNG)).setBit(bits - 1);
    }
    private static byte[] gcmOpen(SecretKey key, byte[] aad, byte[] blob) throws Exception {
        if (blob.length < 28) {
            throw new AEADBadTagException("blob too short");
        } else {
            byte[] nonce = new byte[12];
            System.arraycopy(blob, 0, nonce, 0, 12);
            byte[] ct = new byte[blob.length - 12];
            System.arraycopy(blob, 12, ct, 0, ct.length);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(2, key, new GCMParameterSpec(128, nonce));
            if (aad != null) {
                c.updateAAD(aad);
            }

            return c.doFinal(ct);
        }
    }
    private static String b64enc(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
    private static byte[] b64dec(String s) {
        return Base64.getDecoder().decode(s);
    }
    private static byte[] gcmSeal(SecretKey key, byte[] aad, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(1, key, new GCMParameterSpec(128, nonce));
        if (aad != null) {
            c.updateAAD(aad);
        }

        byte[] ct = c.doFinal(plaintext);
        ByteBuffer bb = ByteBuffer.allocate(12 + ct.length);
        bb.put(nonce).put(ct);
        return bb.array();
    }
    private static byte[] signMessage(byte[] message, PrivateKey privateKey) throws Exception {
        // Utilisation de SHA256 avec MGF1/SHA256 pour PSS
        Signature signer = Signature.getInstance("RSASSA-PSS"); // Utilisez BouncyCastle ou équivalent pour PSS
        // Si BouncyCastle n'est pas disponible, "SHA256withRSAandMGF1" peut parfois fonctionner.
        // Pour la compatibilité JCE standard sans fournisseur externe:
        // Signature signer = Signature.getInstance("SHA256withRSA"); // Cela utiliserait PKCS#1 v1.5, pas PSS
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signer.initSign(privateKey, RNG);
        signer.update(message);
        return signer.sign();
    }

    // 4. Chiffrement RSA/OEAP
    private static byte[] encryptRsaOaep(byte[] data, PublicKey publicKey) throws Exception {
        // Utilisation de OAEP avec SHA-256 comme fonction de hachage
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, RNG);
        return cipher.doFinal(data);
    }
}