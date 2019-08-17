package satokentestnet.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import satokentestnet.util.Bytes;
import satokentestnet.util.Keys;
import satokentestnet.util.Strings;

/**
 * Helper class with Key Derivation functions.
 *
 * @author Carson Mullins
 */
public class KeyDerivation {

    private KeyDerivation() {
    } // Non-instantiable

    /**
     * Derives a child extended private key from a parent extended private key.
     * An extended private key has 64 bytes, the left-hand 32-bytes is treated
     * as the master secret key, and the right-hand 32-bytes is treated as the
     * master chain code. Specifications defined in
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>
     *
     * @param xkey_par the parent extended private key.
     * @param i the child index to derive.
     * @param hardened whether the derived child extended key will be hardened
     * (note: hardened means i = i + (2^31 - 1), or i = 0x80000000 | i).
     * @return the child extended private key derived at child index i.
     */
    public static byte[] CKDpriv(byte[] xkey_par, int i, boolean hardened) {
        // Split xkey_par into two 32-byte sequences, I_L and I_R.
        // Use parse256(I_L) as master secret key (k_par), and I_R as
        // master chain code (c_par).
        byte[] k_par = Arrays.copyOfRange(xkey_par, 0, xkey_par.length / 2);
        byte[] c_par = Arrays.copyOfRange(xkey_par, xkey_par.length / 2, xkey_par.length);
        BigInteger k_par_bigInt = new BigInteger(1, k_par);
        // If Non-Hardened derivation: Public Key is needed in compressed form. 
        // Calculate K_par as Public Key where K_par = k_par * G
        // Note: Scalar Point Multiplication
        // If Hardened: let I = HMAC-SHA512(Key = c_par, Data = 0x00 || 
        // ser256(k_par) || ser32(i)). (Note: The 0x00 pads the private key
        // to make it 33 bytes long.)
        // If not (normal child): let I = HMAC-SHA512(Key = c_par, Data = serP
        // (K_par) || ser32(i)).
        i = (hardened) ? 0x80000000 | i : i;
        byte[] data;
        byte[] i_bytes = ByteBuffer.allocate(4).putInt(i).array();
        if (hardened) {
            data = Bytes.concat(
                    new byte[]{0x00}, Bytes.concat(k_par, i_bytes));
        } else {
            PublicKey K = Keys.toKeyPair(k_par).getPublic();
            byte[] compressed_K_par = Keys.toBytes(K);
            data = Bytes.concat(compressed_K_par, i_bytes);
        }
        byte[] I = Hash.hmac(c_par, data);

        // Split I into two 32-byte sequences, I_L and I_R.
        // The returned child key k_i is parse256(I_L) + k_par (mod n).
        // The returned chain code c_i is I_R.
        byte[] I_L = Arrays.copyOfRange(I, 0, I.length / 2);
        byte[] I_R = Arrays.copyOfRange(I, I.length / 2, I.length);

        BigInteger I_L_bigInt = new BigInteger(1, I_L);
        BigInteger res = I_L_bigInt.add(k_par_bigInt);
        res = res.mod(CurveParams.n);

        byte[] k_i = Strings.toBytes(String.format("%064X", res));
        byte[] c_i = I_R;

        byte[] xkey_i = Bytes.concat(k_i, c_i);
        return xkey_i;
    }

    /**
     * Derives a child extended public key from a parent extended public key. An
     * extended public key has 65 bytes, the left-hand 33-bytes is treated as
     * the public key, and the right-hand 32-bytes is treated as the master
     * chain code. Specifications defined in
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>
     *
     * @param xkey_par the parent extended public key.
     * @param i the child index to derive.
     * @return the child extended public key derived at child index i.
     */
    public static byte[] CKDpub(byte[] xkey_par, int i) {
        byte[] chain_code = Arrays.copyOfRange(xkey_par, 33, xkey_par.length);
        byte[] data = Bytes.concat(Arrays.copyOfRange(xkey_par, 0, 33), ByteBuffer.allocate(4).putInt(i).array());
        byte[] I = Hash.hmac(chain_code, data);
        byte[] I_L = Arrays.copyOfRange(I, 0, 32);
        byte[] I_R = Arrays.copyOfRange(I, 32, 64);
        // I_L is treated as a private key
        byte[] pubAdd = createPubKey(I_L, CurveParams.G);
        ECPoint pubAddPoint = ((ECPublicKey) Keys.toPubKey(pubAdd)).getW();
        byte[] pubPar = Arrays.copyOfRange(xkey_par, 0, 33);
        ECPoint pubParPoint = ((ECPublicKey) Keys.toPubKey(pubPar)).getW();
        ECPoint childPoint = ScalarMultiply.addPoint(pubAddPoint, pubParPoint);
        byte[] x_bytes = new byte[32];
        byte[] x_raw = childPoint.getAffineX().toByteArray();
        if (x_raw.length > 32) {
            x_bytes = Arrays.copyOfRange(x_raw, x_raw.length - 32, x_raw.length);
        } else if (x_raw.length < 32) {
            System.arraycopy(x_raw, 0, x_bytes, 32 - x_raw.length, x_raw.length);
        } else {
            x_bytes = x_raw;
        }
        byte parity = (byte) (childPoint.getAffineY().testBit(0) ? 0x03 : 0x02);
        byte[] childPubKey = Bytes.concat(new byte[]{parity}, x_bytes);
        return Bytes.concat(childPubKey, I_R);
    }

    /**
     * Derives a child extended public key from a parent extended private key.
     * An extended public key has 65 bytes, the left-hand 33-bytes is treated as
     * the public key, and the right-hand 32-bytes is treated as the master
     * chain code. Specifications defined in
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>
     *
     * @param xkey_par the parent extended private key.
     * @param i the child index to derive.
     * @param hardened whether the derived child extended key will be hardened
     * (note: hardened means i = i + (2^31 - 1), or i = 0x80000000 | i).
     * @return the child extended public key derived at child index i.
     */
    public static byte[] NCKDpriv(byte[] xkey_par, int i, boolean hardened) {
        byte[] xKey = CKDpriv(xkey_par, i, hardened);
        byte[] pubKey = createPubKey(Arrays.copyOfRange(xKey, 0, 32), CurveParams.G);
        return Bytes.concat(pubKey, Arrays.copyOfRange(xKey, 32, 64));
    }

    /**
     * Password Based Key Derivation Function 2. Generates a Key object based on
     * a given password, given salt, number of iterations of the underlying hash
     * function, and has a length of {@code dkLen}. The Key is encoded as an AES
     * key.
     *
     * @param password the password used to derive the Key.
     * @param salt the salt used to derive the Key.
     * @param iterations the number of iterations of the underlying hash
     * function SHA-512.
     * @param dkLen the length of the derived Key.
     * @return the Derived AES Key based on the password and salt given.
     */
    public static Key PBKDF2forAES(char[] password, byte[] salt, int iterations, int dkLen) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            KeySpec spec = new PBEKeySpec(password, salt, iterations, dkLen);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
            return secret;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Password Based Key Derivation Function 2. Generates bytes based on a
     * given password, given salt, number of iterations of the underlying hash
     * function, and has a length of 32. These bytes are then used to derive a
     * public key by treating the generated bytes as a private key value.
     *
     * @param password the password used to derive the private key bytes.
     * @param salt the salt used to derive the private key bytes.
     * @return
     */
    public static byte[] PBKDF2toECIES(char[] password, byte[] salt) {
        byte[] prvKey = Hash.PBKDF2(password, salt, 2048, 32 * 8);
        return createPubKey(prvKey, CurveParams.G);
    }

    /**
     * Performs Scalar Multiplication about a specified point and returns the
     * public key's bytes.
     *
     * @param prvKey the private key used in scalar multiplication.
     * @param genPoint the generator point used in scalar multiplication.
     * @return the public key created by multiplying {@code prvKey} by
     * {@code genPoint}.
     */
    public static byte[] createPubKey(byte[] prvKey, ECPoint genPoint) {
        BigInteger masterS = new BigInteger(1, prvKey);
        ECPoint point = ScalarMultiply.scalmult(genPoint, masterS);
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        byte[] x_bytes = new byte[32];
        byte[] x_raw = x.toByteArray();
        if (x_raw.length > 32) {
            x_bytes = Arrays.copyOfRange(x_raw, x_raw.length - 32, x_raw.length);
        } else if (x_raw.length < 32) {
            System.arraycopy(x_raw, 0, x_bytes, 32 - x_raw.length, x_raw.length);
        } else {
            x_bytes = x_raw;
        }
        byte parity = (byte) (y.testBit(0) ? 0x03 : 0x02);
        return Bytes.concat(new byte[]{parity}, x_bytes);
    }
}
