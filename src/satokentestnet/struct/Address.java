package satokentestnet.struct;

import satokentestnet.util.Bytes;
import satokentestnet.util.Strings;

/**
 * Neutered version of {@link KeyData} with only the Public Key Hash, the
 * Address, and whether the address has been seen or not.
 *
 * @author Carson Mullins
 */
public class Address {

    private final byte[] pubKeyHash;
    private final String address;
    private boolean seen;

    /**
     * Constructor for an Address.
     *
     * @param pubKeyHash the Public Key Hash of the address.
     */
    public Address(byte[] pubKeyHash) {
        this.pubKeyHash = pubKeyHash;
        address = Strings.encodeAddress(pubKeyHash);
        seen = false;
    }

    /**
     *
     * @return the public key hash of this Address.
     */
    public byte[] getPubKeyHash() {
        return pubKeyHash;
    }

    /**
     *
     * @return the Base58 encoded address of the Public Key Hash.
     */
    public String getAddress() {
        return address;
    }

    /**
     * Marks this Address object as being seen before.
     */
    public void seen() {
        seen = true;
    }

    /**
     *
     * @return whether the Address has been seen.
     */
    public boolean isSeen() {
        return seen;
    }

    /**
     * Helper method for converting 21 bytes into an Address object.
     *
     * @param data the first byte indicates whether the address has been seen,
     * the remaining 20 bytes are the {@code pubKeyHash}.
     * @return the Address object whose serialized data is equivalent to the
     * {@code data} param.
     */
    public static Address deserialize(byte[] data) {
        byte[] pubKeyHash = new byte[20];
        System.arraycopy(data, 1, pubKeyHash, 0, pubKeyHash.length);
        Address address = new Address(pubKeyHash);
        if (data[0] == (byte) 0x01) {
            address.seen();
        }
        return address;
    }

    /**
     * Serializes this Address object in the following format: seen (1 byte) ||
     * pubKeyHash (20 bytes).
     *
     * @return the serialized Address object.
     */
    public byte[] serialize() {
        return Bytes.concat(new byte[]{(byte) (seen ? 0x01 : 0x00)}, pubKeyHash);
    }

    /**
     * Checks whether an object is an Address, and whether the {@code address}
     * of this Address object matches the {@code address} of the given object.
     *
     * @param o the object to check equality of.
     * @return whether the addresses of both objects match.
     */
    @Override
    public boolean equals(Object o) {
        if (o.getClass() != Address.class) {
            return false;
        }
        return ((Address) o).address.equals(this.address);
    }
}
