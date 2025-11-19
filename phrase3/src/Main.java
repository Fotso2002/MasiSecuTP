import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;

public class Main {
    private static final BigInteger G = BigInteger.valueOf(2L);
    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final SecureRandom RNG = new SecureRandom();
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
            BigInteger Z = B.modPow(b, P);


        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.out.println("Hello world!");
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
    private static String b64enc(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}