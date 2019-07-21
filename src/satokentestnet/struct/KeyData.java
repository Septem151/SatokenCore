package satokentestnet.struct;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import satokentestnet.crypto.Hash;
import satokentestnet.util.Keys;
import satokentestnet.util.Strings;

/**
 * A data structure containing information about a KeyPair. Information
 * includes: PrivateKey object, PublicKey object, the Hash160 of the Public Key,
 * the Address associated with the hash of the public key, and whether or not
 * the key has been seen.
 *
 * @author Carson Mullins
 */
public class KeyData {

    public PrivateKey prvKey;
    public PublicKey pubKey;
    public byte[] pubKeyHash;
    public String address;
    public boolean seen;

    /**
     * Default constructor of a KeyData object.
     *
     * @param keyPair the KeyPair that this object is representing.
     */
    public KeyData(KeyPair keyPair) {
        this.prvKey = keyPair.getPrivate();
        this.pubKey = keyPair.getPublic();
        this.pubKeyHash = Hash.hash160(Keys.toBytes(pubKey));
        this.address = Strings.encodeAddress(pubKeyHash);
        this.seen = false;
    }
}
