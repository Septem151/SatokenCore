package satokentestnet.struct;

import java.nio.ByteBuffer;
import java.util.Arrays;
import satokentestnet.util.Bytes;
import satokentestnet.util.Strings;

/**
 * A TransactionOutput contains two components: A Value and a Recipient's Public
 * Key Hash. Also contains some helper methods to retrieve helpful information
 * such as the address associated with the Public Key Hash, serializing into
 * bytes, deserializing from bytes, and a dump format.
 *
 * @author Carson Mullins
 */
public class TransactionOutput {

    private final long value;
    private final byte[] pubKeyHash;

    /**
     * Default constructor for creating a TransactionOutput. Generally, a
     * TransactionOutput is created for a recipient whom we don't have a
     * PublicKey object created for, and it would be a waste of computation
     * power to convert to a PublicKey object and then back again into bytes.
     *
     * @param value the amount of Satoken that this output holds.
     * @param pubKeyHash the recipient's PubKeyHash, whose spender must prove
     * ownership of.
     */
    public TransactionOutput(long value, byte[] pubKeyHash) {
        this.value = value;
        this.pubKeyHash = pubKeyHash;
    }

    /**
     * @return the value of Satoken this output holds.
     */
    public long getValue() {
        return value;
    }

    /**
     * @return the Base58 address that this output's PubKeyHash represents.
     */
    public String getAddress() {
        return Strings.encodeAddress(pubKeyHash);
    }

    /**
     * @return the recipient's PubKeyHash, whose spender must prove ownership
     * of.
     */
    public byte[] getPubKeyHash() {
        return pubKeyHash;
    }

    /**
     * Deserializes a byte representation of a TransactionOutput into an object.
     *
     * @param data the bytes of a serialized TransactionOutput.
     * @return a TransactionOutput object whose serialization is equivalent to
     * the data supplied.
     */
    public static TransactionOutput deserialize(byte[] data) {
        long value = ByteBuffer.wrap(Arrays.copyOfRange(data, 0, 8)).getLong();
        byte[] pubKeyHash = Arrays.copyOfRange(data, 8, 28);
        return new TransactionOutput(value, pubKeyHash);
    }

    /**
     * Serializes an output object into byte form. Format: value (8 bytes) ||
     * pubKeyHash (20 bytes)
     *
     * @return a serialized representation of the output.
     */
    public byte[] serialize() {
        return Bytes.concat(ByteBuffer.allocate(8).putLong(value).array(), pubKeyHash);
    }

    /**
     * @return the dump format of the output object.
     */
    @Override
    public String toString() {
        String res = "      Recipient: " + getAddress() + "\n";
        String amount = String.format("%09d", value);
        amount = amount.substring(0, amount.length() - 8) + "." + amount.substring(amount.length() - 8) + " STK";
        res += "         Amount: " + amount + "\n";
        return res;
    }
}
