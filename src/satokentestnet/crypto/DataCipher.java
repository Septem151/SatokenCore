package satokentestnet.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import satokentestnet.util.Bytes;

/**
 * Helper class for encoding data and decoding data using AES encryption.
 *
 * @author Carson Mullins
 */
public class DataCipher {

    public static final byte encryptionFlag = 0x01;
    private static final int saltLength = 6; // bytes
    private static final int encryptFlagLength = 1; // bytes
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
