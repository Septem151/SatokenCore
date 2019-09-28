package satokentestnet.struct;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.Arrays;
import satokentestnet.crypto.Hash;
import satokentestnet.util.Bytes;
import satokentestnet.util.Keys;

/**
 * A TransactionInput contains 4 components: a referenced transaction hash, an
 * index of the output referenced in the transaction, the bytes of a public key
 * (compressed), and the bytes of a SHA1withECDSA signature. The signature signs
 * the hash of whatever transaction this input is located in (with all input
 * signatures replaced with 0x00).
 *
 * @author Carson Mullins
 */
public class TransactionInput {

    private final byte[] refTx;
    private final int txOI;
    private final byte[] pubKey;
    private byte[] sig;

    /**
     * Default constructor of a TransactionInput. Since almost all inputs are
     * created by a wallet, a PublicKey can be used since the wallet stores keys
     * as objects.
     *
     * @param refTx the referenced transaction hash in bytes.
     * @param txOI the referenced transaction's output index.
     * @param pubKey the public key that, when hashed, will match the referenced
     * output's pubKeyHash.
     */
    public TransactionInput(byte[] refTx, int txOI, PublicKey pubKey) {
        this.refTx = refTx;
        this.txOI = txOI;
        this.pubKey = Keys.toBytes(pubKey);
        sig = new byte[]{0x00};
    }

    /**
     * Coinbase constructor of a TransactionInput. Since a Coinbase input
     * contains arbitrary data in its scriptSig, the constructor allows for
     * direct entry.
     *
     * @param refTx the referenced transaction hash in bytes (for Coinbase: 32
     * 0x00 bytes)
     * @param txOI the referenced transaction's output index (for Coinbase: -1)
     * @param scriptSig the pubKey bytes || signature bytes (for Coinbase, this
     * can be arbitrary data up to 100 bytes (must include the block's height
     * and extranonce as first 8 bytes).
     */
    public TransactionInput(byte[] refTx, int txOI, byte[] scriptSig) {
        this.refTx = refTx;
        this.txOI = txOI;
        if (scriptSig.length < 33) {
            this.pubKey = new byte[0];
            this.sig = scriptSig;
        } else {
            this.pubKey = Arrays.copyOfRange(scriptSig, 0, 33);
            this.sig = Arrays.copyOfRange(scriptSig, 33, scriptSig.length);
        }
    }

    /**
     * Allows for consistent creation of Coinbase inputs.
     *
     * @param height the block height that the input will be included in.
     * @param extraNonce the extranonce of the mined block.
     * @return a TransactionInput whose scriptSig contains: height (4 bytes) ||
     * extranonce (4 bytes)
     */
    public static TransactionInput getCoinbaseInput(int height, int extraNonce) {
        byte[] heightBytes = ByteBuffer.allocate(4).putInt(height).array();
        byte[] extraNonceBytes = ByteBuffer.allocate(4).putInt(extraNonce).array();
        byte[] scriptSig = new byte[8];
        System.arraycopy(heightBytes, 0, scriptSig, 0, 4);
        System.arraycopy(extraNonceBytes, 0, scriptSig, scriptSig.length - 4, 4);
        return new TransactionInput(new byte[32], -1, scriptSig);
    }

    /**
     * Clears the input's signature and fills with a 0x00 byte.
     */
    public void clearSig() {
        this.sig = new byte[]{0x00};
    }

    /**
     * @param sig the sig bytes to set.
     */
    public void setSig(byte[] sig) {
        this.sig = sig;
    }

    /**
     * @return the input's sig bytes.
     */
    public byte[] getSig() {
        return sig;
    }

    /**
     * @return the input's scriptSig bytes. Format: pubKey || sig
     */
    public byte[] getScriptSig() {
        return Bytes.concat(pubKey, sig);
    }

    /**
     * @return the input's pubKey in PublicKey object form.
     */
    public PublicKey getPubKey() {
        return Keys.toPubKey(pubKey);
    }

    /**
     * @return the Hash160 of the input's pubKey. Assists in determining
     * ownership of the referenced TransactionOutput.
     */
    public byte[] getPubKeyHash() {
        return Hash.hash160(pubKey);
    }

    /**
     * @return the referenced transaction's hash in bytes.
     */
    public byte[] getRefTx() {
        return refTx;
    }

    /**
     * @return the index of the referenced transaction's output that this input
     * consumes.
     */
    public int getTxOI() {
        return txOI;
    }

    /**
     * Serializes an input object into byte form. Format: refTx (32 bytes) ||
     * txOI (4 bytes) || sigLength (4 bytes) || scriptSig (varies)
     *
     * @return a serialized representation of the input.
     */
    public byte[] serialize() {
        int sigLength = pubKey.length + sig.length;
        byte[] scriptSig = Bytes.concat(pubKey, sig);
        byte[] data = Bytes.concat(refTx, ByteBuffer.allocate(4).putInt(txOI).array());
        data = Bytes.concat(data, ByteBuffer.allocate(4).putInt(sigLength).array());
        return Bytes.concat(data, scriptSig);
    }

    /**
     * @return the dump format of the input object.
     */
    @Override
    public String toString() {
        String res = "Ref Transaction: " + Bytes.toHex(refTx) + "\n";
        res += "   Output Index: " + txOI + "\n";
        String pubKeyStr = Bytes.toHex(pubKey);
        res += "     Public Key: " + (pubKeyStr.length() != 0 ? pubKeyStr : "COINBASE TXN") + "\n";
        res += "      Signature: " + Bytes.toHex(sig) + "\n";
        return res;
    }
}
