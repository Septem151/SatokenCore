package satokentestnet.util;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import satokentestnet.crypto.CurveParams;
import satokentestnet.crypto.ScalarMultiply;

public final class Keys {

    private Keys() {
    } // Non-instantiable

    /**
     * Generates a KeyPair object with a random private key.
     * @return a KeyPair object with random private key on the SECP256K1 elliptic curve.
     */
    public static KeyPair randomKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec spec = new ECGenParameterSpec("secp256k1");
            kpg.initialize(spec);
            return kpg.genKeyPair();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Converts the bytes of a private key into a KeyPair object.
     * @param privateKeyBytes the S value of a private key represented in bytes.
     * @return a KeyPair object whose private key has the given S value and whose public key
     * is cryptographically related to the private key along the SECP256K1 elliptic curve.
     */
    public static KeyPair toKeyPair(byte[] privateKeyBytes) {
        try {
            BigInteger s = new BigInteger(1, privateKeyBytes);
            ECPrivateKeySpec prvKeySpec = new ECPrivateKeySpec(s, CurveParams.ecSpec);

            ECPoint W = ScalarMultiply.scalmult(CurveParams.G, s);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(W, CurveParams.ecSpec);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey k = keyFactory.generatePrivate(prvKeySpec);
            PublicKey K = keyFactory.generatePublic(pubKeySpec);
            return new KeyPair(K, k);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Converts a given Key (Public or Private) into its respective bytes.
     * @param key the Key to convert (Public or Private).
     * @return PublicKey -> Compressed Public Key bytes, PrivateKey -> S value.
     */
    public static byte[] toBytes(Key key) {
        if (key instanceof PublicKey) {
            ECPublicKey K = (ECPublicKey) key;
            BigInteger K_x = K.getW().getAffineX();
            BigInteger K_y = K.getW().getAffineY();
            byte[] K_x_bytes = new byte[32];
            byte[] K_x_raw = K_x.toByteArray();
            if (K_x_raw.length > 32) {
                K_x_bytes = Arrays.copyOfRange(K_x_raw, K_x_raw.length - 32, K_x_raw.length);
            } else if (K_x_raw.length < 32) {
                System.arraycopy(K_x_raw, 0, K_x_bytes, 32 - K_x_raw.length, K_x_raw.length);
            } else {
                K_x_bytes = K_x_raw;
            }
            byte parity = (byte) (K_y.testBit(0) ? 0x03 : 0x02);
            byte[] K_comp = Bytes.concat(new byte[]{parity}, K_x_bytes);
            return K_comp;
        } else {
            ECPrivateKey k = (ECPrivateKey) key;
            BigInteger S = k.getS();
            byte[] k_raw = S.toByteArray();
            byte[] k_bytes = new byte[32];
            if (k_bytes.length > 32) {
                k_bytes = Arrays.copyOfRange(k_raw, k_raw.length - 32, k_raw.length);
            } else if (k_bytes.length < 32) {
                System.arraycopy(k_raw, 0, k_bytes, 32 - k_raw.length, k_raw.length);
            } else {
                k_bytes = k_raw;
            }
            return k_bytes;
        }
    }

    /**
     * Converts the given public key bytes (in compressed or uncompressed form)
     * into a PublicKey object.
     * @param pubKeyBytes the bytes to convert (if compressed, first decompresses the key).
     * @return the PublicKey object whose X and Y values match the given bytes.
     */
    public static PublicKey toPubKey(byte[] pubKeyBytes) {
        try {
            if (pubKeyBytes[0] == 0x02 || pubKeyBytes[0] == 0x03) {
                pubKeyBytes = decompressPubKey(pubKeyBytes);
            }
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubKeyBytes, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(pubKeyBytes, 33, 65));
            ECPoint W = new ECPoint(x, y);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(W, CurveParams.ecSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Decompresses the given public key bytes.
     * @param pubKeyBytes the bytes of a public key in compressed form (0x02 or 0x03 || X value).
     * @return the bytes of a public key in uncompressed form (0x04 || X value || Y value).
     */
    public static byte[] decompressPubKey(byte[] pubKeyBytes) {
        byte[] K_x_bytes = new byte[32];
        System.arraycopy(pubKeyBytes, 1, K_x_bytes, 0, K_x_bytes.length);
        byte parity = pubKeyBytes[0];
        BigInteger K_x = new BigInteger(1, K_x_bytes);
        BigInteger y_square = K_x.modPow(
                BigInteger.valueOf(3), CurveParams.p).add(CurveParams.b)
                .mod(CurveParams.p);
        BigInteger y_root = y_square.modPow(
                CurveParams.p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)),
                CurveParams.p);
        BigInteger K_y;
        if (parity == 0x02 && y_root.testBit(0)
                || parity == 0x03 && !y_root.testBit(0)) {
            K_y = y_root.negate().mod(CurveParams.p);
        } else {
            K_y = y_root;
        }
        byte[] K_y_bytes = Strings.toBytes(String.format("%064X", K_y));
        byte[] K_uncomp = Bytes.concat(new byte[]{0x04},
                Bytes.concat(K_x_bytes, K_y_bytes));
        return K_uncomp;
    }
}
