package satokentestnet.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import satokentestnet.util.Bytes;
import satokentestnet.util.Keys;

/**
 * Helper class for encoding data and decoding data using AES encryption.
 *
 * @author Carson Mullins
 */
public class DataCipher {

    public static final byte encryptionFlag = 0x01;
    private static final int saltLength = 6; // bytes
    private static final int encryptFlagLength = 1; // bytes
    private static final int versionLength = 4; // bytes
    private static final int hashKeyLength = 32; // bytes
    private static final int keyLength = 32 * 8; // bits
    private static final int iterations = 2048;

    private DataCipher() {
    } // Non-instantiable

    /**
     * Encrypts data using AES Cipher.
     *
     * @param data the data to encrypt.
     * @param password the password to derive a key with for AES encryption.
     * @return the encrypted data bytes.
     */
    public static byte[] encryptData(byte[] data, char[] password) {
        byte[] salt, hashKey, encryptedData;
        salt = generateSalt();
        Key key = KeyDerivation.PBKDF2forAES(password, salt, iterations, keyLength);
        hashKey = Hash.sha256(key.getEncoded());
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedData = cipher.doFinal(data);
            byte[] flag = new byte[]{(password.length == 0) ? 0x00 : encryptionFlag};
            encryptedData = Bytes.concat(flag, Bytes.concat(salt, Bytes.concat(hashKey, encryptedData)));
            return encryptedData;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts data using AES Cipher.
     *
     * @param data the data to decrypt.
     * @param password the password used for deriving the key for AES
     * decryption.
     * @return the decrypted data bytes.
     * @throws InvalidPasswordException if the password given does not derive
     * the necessary key to decipher the data.
     */
    public static byte[] decryptData(byte[] data, char[] password) throws InvalidPasswordException {
        int offset = encryptFlagLength;
        byte[] salt = Arrays.copyOfRange(data, offset, offset + saltLength);
        offset += saltLength;
        byte[] expectedHashKey = Arrays.copyOfRange(data, offset, offset + hashKeyLength);
        Key key = KeyDerivation.PBKDF2forAES(password, salt, iterations, keyLength);
        byte[] hashKey = Hash.sha256(key.getEncoded());
        if (!Arrays.equals(expectedHashKey, hashKey)) {
            throw new InvalidPasswordException();
        }
        offset += hashKeyLength;
        byte[] encryptedData = Arrays.copyOfRange(data, offset, data.length);
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypts data with ECIES (using an AES cipher of the symmetric public
     * key's X component).
     *
     * @param version the version bytes of whatever data is encrypted.
     * @param data the data to encrypt.
     * @param pubKey the owner's public key (derived by running PBKDF2 on a
     * password with the given salt).
     * @param flag indicates whether the file has a password or not (0x01 for
     * true, 0x00 for false).
     * @param salt the salt used to generate the given {@code pubKey}.
     * @return
     */
    public static byte[] ECIESencrypt(byte[] version, byte[] data, byte[] pubKey, byte[] flag, byte[] salt) {
        PublicKey ownerPubKey = Keys.toPubKey(pubKey);
        byte[] ownerPubHash = Hash.sha256(Keys.toBytes(ownerPubKey));
        byte[] ephemeralPrvKey = new byte[32];
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.nextBytes(ephemeralPrvKey);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
        byte[] ephemeralPubKey = KeyDerivation.createPubKey(ephemeralPrvKey, CurveParams.G);
        byte[] encryptingKey = KeyDerivation.createPubKey(ephemeralPrvKey, ((ECPublicKey) ownerPubKey).getW());
        encryptingKey = Arrays.copyOfRange(encryptingKey, 1, 33);
        byte[] encryptedData = Bytes.concat(version, flag);
        encryptedData = Bytes.concat(encryptedData, salt);
        encryptedData = Bytes.concat(encryptedData, ownerPubHash);
        encryptedData = Bytes.concat(encryptedData, ephemeralPubKey);
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKey secret = new SecretKeySpec(encryptingKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            return Bytes.concat(encryptedData, cipher.doFinal(data));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts data with ECIES (using an AES cipher of the symmetric public
     * key's X component).
     *
     * @param data the data to decrypt, which includes the encryption flag, the
     * version bytes, the salt, expected owner {@code pubKeyHash}, and the
     * ephemeral public key.
     * @param password the password used for deriving the owner's public key.
     * @return the decrypted data bytes.
     * @throws InvalidPasswordException if the password given does not derive
     * the necessary public key that hashes to the expected owner {@code pubKeyHash}.
     */
    public static byte[] ECIESdecrypt(byte[] data, char[] password) throws InvalidPasswordException {
        int offset = encryptFlagLength + versionLength;
        byte[] salt = Arrays.copyOfRange(data, offset, offset += saltLength);
        byte[] expectedPubHash = Arrays.copyOfRange(data, offset, offset += 32);
        byte[] ephemeralPubKey = Arrays.copyOfRange(data, offset, offset += 33);
        byte[] encryptedData = Arrays.copyOfRange(data, offset, data.length);
        byte[] ownerPrvKey = Hash.PBKDF2(password, salt, iterations, keyLength);
        KeyPair ownerKeys = Keys.toKeyPair(ownerPrvKey);
        byte[] ownerPubHash = Hash.sha256(Keys.toBytes(ownerKeys.getPublic()));
        if (!Arrays.equals(ownerPubHash, expectedPubHash)) {
            throw new InvalidPasswordException();
        }
        ECPoint ephemeralPoint = ((ECPublicKey) Keys.toPubKey(ephemeralPubKey)).getW();
        byte[] decryptionKey = KeyDerivation.createPubKey(Keys.toBytes(ownerKeys.getPrivate()), ephemeralPoint);
        decryptionKey = Arrays.copyOfRange(decryptionKey, 1, 33);
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKey secret = new SecretKeySpec(decryptionKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secret);
            return cipher.doFinal(encryptedData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Generates a random salt of {@value #saltLength} bytes in length using a
     * SHA1PRNG entropy source.
     *
     * @return the randomly generated salt bytes.
     */
    public static byte[] generateSalt() {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[saltLength];
            sr.nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

}
