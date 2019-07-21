package satokentestnet.util;

import java.util.Arrays;
import satokentestnet.crypto.Base58Check;

public final class Strings {

    private Strings() {
    } // Non-instantiable

    /**
     * Converts a hexadecimal string representation of bytes into a byte array.
     *
     * @param hex the hexadecimal string (not checked for length correctness).
     * @return the byte array representation of hex value.
     */
    public static byte[] toBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Converts a Base58 Address into a PubKeyHash (RIPEMD-160 of SHA-256 of a
     * public Key).
     * @param address the Base58 Encoded address to convert.
     * @return the RIPEMD-160 of the SHA-256 hash of a Public Key.
     * @throws IllegalArgumentException if the address is not a Base58Check encoded address.
     */
    public static byte[] decodeAddress(String address) throws IllegalArgumentException {
        byte[] decoded = Base58Check.base58ToBytes(address);
        return Arrays.copyOfRange(decoded, 1, decoded.length);
    }

    /**
     * Converts a PubKeyHash (RIPEMD-160 of SHA-256 of a public Key) into a 
     * Base58 encoded address.
     * @param pubKeyHash the PubKeyHash (RIPEMD-160 of SHA-256 of a public Key) to convert.
     * @return the Base58Check encoded address.
     */
    public static String encodeAddress(byte[] pubKeyHash) {
        return Base58Check.bytesToBase58(
                Bytes.concat(new byte[]{0x00}, pubKeyHash));
    }

    /**
     * Constructs a String where the first half is a Transaction Hash (in hexadecimal)
     * and the second half is a Transaction Output index, split by a colon ":".
     * @param refTx the referenced Transaction Hash in bytes.
     * @param txOI the referenced Transaction output index.
     * @return a String concatenating both the refTx and txOI with a ":" delimiter.
     */
    public static String coinPointer(byte[] refTx, int txOI) {
        return Bytes.toHex(refTx) + ":" + String.valueOf(txOI);
    }

}
