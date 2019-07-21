package satokentestnet.util;

public class Bytes {

    private final static char[] hexArray = "0123456789abcdef".toCharArray();

    private Bytes() {

    } // Non-instantiable

    /**
     * Concatenates two byte arrays into a single byte array.
     *
     * @param b1 the first byte array.
     * @param b2 the second byte array.
     * @return the byte array equal to b1 || b2.
     */
    public static byte[] concat(byte[] b1, byte[] b2) {
        byte[] output = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, output, 0, b1.length);
        System.arraycopy(b2, 0, output, b1.length, b2.length);
        return output;
    }

    /**
     * Converts a byte array into its hexadecimal string representation.
     *
     * @param bytes the byte array to convert.
     * @return a hexadecimal string representation of bytes.
     */
    public static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = hexArray[v >>> 4];
            hexChars[i * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Converts a byte array into a boolean array representing the bits of the
     * bytes.
     *
     * @param data the byte array to convert.
     * @return the boolean array representation of the bits in data.
     */
    public static boolean[] toBits(byte[] data) {
        boolean[] bits = new boolean[data.length * 8];
        for (int i = 0; i < data.length; ++i) {
            for (int j = 0; j < 8; ++j) {
                bits[(i * 8) + j] = (data[i] & (1 << (7 - j))) != 0;
            }
        }
        return bits;
    }

    /**
     * Converts a boolean array representing bits into its integer value.
     *
     * @param bits the boolean array to convert.
     * @return the integer value of the bits.
     */
    public static int bitsToInt(boolean[] bits) {
        int n = 0, l = bits.length;
        for (int i = 0; i < l; ++i) {
            n = (n << 1) + (bits[i] ? 1 : 0);
        }
        return n;
    }
}
