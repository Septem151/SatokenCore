package satokentestnet.client;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.stream.Stream;
import satokentestnet.crypto.Hash;
import satokentestnet.crypto.KeyDerivation;
import satokentestnet.struct.Blockchain;
import satokentestnet.struct.KeyData;
import satokentestnet.struct.Transaction;
import satokentestnet.struct.TransactionInput;
import satokentestnet.struct.TransactionOutput;
import satokentestnet.util.Bytes;
import satokentestnet.util.Keys;
import satokentestnet.util.Strings;

/**
 * A Wallet contains keys that are derived using a given derivation path, from a
 * given mnemonic and passphrase. Also contains business logic to create a
 * transaction and add it to the blockchain's Mempool.
 *
 * @author Carson Mullins
 */
public class Wallet {

    public static final String defaultDerivation = "m/0'/0'";
    public static final int keyLookAhead = 3;

    private final String derivationPath;
    private final char[] passphrase, mnemonic;
    private final HashMap<String, TransactionOutput> localUTXOs;
    private final ArrayList<KeyData> internalKeys;
    private final ArrayList<KeyData> externalKeys;
    private byte[] xkeyInternal, xkeyExternal;
    private long balance;

    /**
     * Default constructor that derives a mnemonic phrase from a
     * cryptographically secure entropy source from which keys are derived. Keys
     * are continuously derived until there have been {@value #keyLookAhead}
     * unused keys found in a row.
     *
     * @param passphrase the extra bits of entropy used as salt for deriving a
     * seed.
     * @param derivationPath the hierarchical path to take when deriving
     * addresses.
     */
    Wallet(char[] passphrase, String derivationPath) {
        this.passphrase = passphrase;
        this.derivationPath = derivationPath;
        mnemonic = generateMnemonic();
        localUTXOs = new HashMap<>();
        internalKeys = new ArrayList<>();
        externalKeys = new ArrayList<>();
        initKeys();
    }

    /**
     * Secondary constructor for Deserialized wallet data. Used when decrypting
     * pre-existing wallet file data. Keys are continuously derived until there
     * have been {@value #keyLookAhead} unused keys found in a row.
     *
     * @param mnemonic the mnemonic the wallet will create a seed from.
     * @param passphrase the passphrase the wallet will create a seed from.
     * @param derivationPath the derivation path that the keys will be derived
     * from.
     */
    Wallet(char[] mnemonic, char[] passphrase, String derivationPath) {
        this.mnemonic = mnemonic;
        this.passphrase = passphrase;
        this.derivationPath = derivationPath;
        localUTXOs = new HashMap<>();
        internalKeys = new ArrayList<>();
        externalKeys = new ArrayList<>();
        initKeys();
    }

    /**
     * Initializes the wallet with keys, deriving more until
     * {@value #keyLookAhead} keys have been derived without one being
     * previously seen. Keys are split up into two lists: External keys (used
     * for receiving payments), and Internal keys (used for receiving change).
     * The two lists are derived from different paths. External keys are derived
     * from index 0, and internal keys are derived from the index 1.
     */
    private void initKeys() {
        byte[] seed = Hash.PBKDF2(mnemonic,
                ("mnemonic" + new String(passphrase)).getBytes(StandardCharsets.UTF_8),
                2048, 64 * 8);
        byte[] xkey = Hash.hmac("Bitcoin seed".getBytes(StandardCharsets.UTF_8), seed);
        String[] levels = derivationPath.split("/");
        for (int i = 1; i < levels.length; i++) {
            boolean hardened = false;
            int index = -1;
            try {
                if (levels[i].contains("'")) {
                    index = Integer.parseInt(levels[i].substring(0, levels[i].length() - 1));
                    hardened = true;
                } else {
                    index = Integer.parseInt(levels[i]);
                }
            } catch (NumberFormatException ex) {
                System.out.println("Invalid Derivation Path, unable to proceed.");
                System.exit(1);
            }
            xkey = KeyDerivation.CKDpriv(xkey, index, hardened);
        }
        xkeyExternal = KeyDerivation.CKDpriv(xkey, 0, false);
        xkeyInternal = KeyDerivation.CKDpriv(xkey, 1, false);
        int count = 0;
        while (count < keyLookAhead) {
            KeyData keyData = genInternalKey();
            if (!Blockchain.getInstance().getUTXOs(keyData.pubKeyHash).isEmpty()) {
                keyData.seen = true;
                count = 0;
            } else {
                count++;
            }
        }
        count = 0;
        while (count < keyLookAhead) {
            KeyData keyData = genExternalKey();
            if (!Blockchain.getInstance().getUTXOs(keyData.pubKeyHash).isEmpty()) {
                keyData.seen = true;
                count = 0;
            } else {
                count++;
            }
        }
    }

    /**
     * Generates a new internal key for change outputs.
     *
     * @return the derived key wrapped in a KeyData object.
     */
    public KeyData genInternalKey() {
        byte[] xkeyChild = KeyDerivation.CKDpriv(xkeyInternal, internalKeys.size(), false);
        KeyData keyData = new KeyData(Keys.toKeyPair(Arrays.copyOfRange(xkeyChild, 0, 32)));
        internalKeys.add(keyData);
        return keyData;
    }

    /**
     * Generates a new external key for receiving Satoken.
     *
     * @return the derived key wrapped in a KeyData object.
     */
    public KeyData genExternalKey() {
        byte[] xkeyChild = KeyDerivation.CKDpriv(xkeyExternal, externalKeys.size(), false);
        KeyData keyData = new KeyData(Keys.toKeyPair(Arrays.copyOfRange(xkeyChild, 0, 32)));
        externalKeys.add(keyData);
        return keyData;
    }

    /**
     * Parses a derivation to check for accuracy. Derivation format is:
     * "m/#[']?/#[']?/... continued. Derivation paths cannot end with a "/".
     *
     * @param derivation the derivation path to check for validity.
     * @return true if the derivation path is valid, false if it is not.
     */
    public static boolean validateDerivation(String derivation) {
        if (derivation.length() < 2) {
            return false;
        }
        if (!derivation.substring(0, 2).equals("m/")) {
            return false;
        }
        if (derivation.endsWith("/")) {
            return false;
        }
        String[] levels = derivation.split("/");
        for (int i = 1; i < levels.length; i++) {
            try {
                if (levels[i].contains("'")) {
                    Integer.parseInt(levels[i].substring(0, levels[i].length() - 1));
                } else {
                    Integer.parseInt(levels[i]);
                }
            } catch (NumberFormatException ex) {
                return false;
            }
        }
        return true;
    }

    /**
     * Generates a 12-word mnemonic phrase using 16 bytes (128 bits) of entropy
     * from a cryptographically secure pseudo-random number generator, SHA1PRNG.
     *
     * @return the generated 12 words of the mnemonic with space separators.
     */
    private char[] generateMnemonic() {
        // Generate 128-bit Random Number for Entropy
        byte[] ENT = new byte[16];
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.nextBytes(ENT);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
        // Hash the Entropy value
        byte[] HASH = Hash.sha256(ENT);
        // Copy first 4 bits of Hash as Checksum
        boolean[] CS = Arrays.copyOfRange(Bytes.toBits(HASH), 0, 4);
        // Add Checksum to the end of Entropy bits
        boolean[] ENT_CS = Arrays.copyOf(Bytes.toBits(ENT), Bytes.toBits(ENT).length + CS.length);
        System.arraycopy(CS, 0, ENT_CS, Bytes.toBits(ENT).length, CS.length);
        // Split ENT_CS into groups of 11 bits and creates String array for
        // mnemonicWords
        String mnemonicWords = "";
        for (int i = 0; i < 12; i++) {
            boolean[] numBits = Arrays.copyOfRange(ENT_CS, i * 11, i * 11 + 11);
            int index = Bytes.bitsToInt(numBits);
            try (Stream<String> lines = Files.lines(Paths.get(Driver.wordListPath))) {
                mnemonicWords += lines.skip(index).findFirst().get();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            if (i < 11) {
                mnemonicWords += " ";
            }
        }
        return mnemonicWords.toCharArray();
    }

    /**
     * Updates the wallet's balance by iterating through all derived keys and
     * checking if there are any related UTXOs in the Blockchain's Chainstate
     * and Mempool. TODO: Find a way to know if there is unconfirmed balance.
     */
    public void updateBalance() {
        balance = 0;
        localUTXOs.clear();
        HashMap<String, TransactionOutput> UTXOset;
        for (KeyData key : internalKeys) {
            UTXOset = Blockchain.getInstance().getUTXOs(key.pubKeyHash);
            if (UTXOset.isEmpty()) {
                continue;
            }
            key.seen = true;
            for (Map.Entry<String, TransactionOutput> entry : UTXOset.entrySet()) {
                if (Blockchain.getInstance().isSpentUTXO(entry.getKey())) {
                    continue;
                }
                localUTXOs.put(entry.getKey(), entry.getValue());
                balance += entry.getValue().getValue();
            }
        }
        for (KeyData key : externalKeys) {
            UTXOset = Blockchain.getInstance().getUTXOs(key.pubKeyHash);
            if (UTXOset.isEmpty()) {
                continue;
            }
            key.seen = true;
            for (Map.Entry<String, TransactionOutput> entry : UTXOset.entrySet()) {
                if (Blockchain.getInstance().isSpentUTXO(entry.getKey())) {
                    continue;
                }
                localUTXOs.put(entry.getKey(), entry.getValue());
                balance += entry.getValue().getValue();
            }
        }
    }

    /**
     * Formats the wallet's balance in the format: 0.00000000 STK
     *
     * @return the formatted balance as a String.
     */
    public String printBalance() {
        String balStr = String.format("%09d", balance);
        balStr = balStr.substring(0, balStr.length() - 8) + "." + balStr.substring(balStr.length() - 8) + " STK";
        return balStr;
    }

    /**
     * Attempts to construct a new Transaction that has the given outputs and
     * signs it.
     *
     * @param outputs the outputs to include in the transaction.
     * @return the signed Transaction with the given outputs + change (if
     * needed) and inputs to match. If the wallet does not have enough balance,
     * {@code null} is returned.
     */
    public Transaction buildTransaction(ArrayList<TransactionOutput> outputs) {
        Blockchain blockchain = Blockchain.getInstance();
        long totalValue = 0;
        Transaction transaction = new Transaction();
        // Add Outputs to transaction
        for (TransactionOutput output : outputs) {
            transaction.add(output);
            totalValue += output.getValue();
        }
        // Check if wallet balance is enough
        if (totalValue > this.getBalance()) {
            Driver.cli.println("\nNot enough funds to create Transaction.\n");
            return null;
        }
        // Create Inputs from local UTXOs
        ArrayList<PrivateKey> signingKeys = new ArrayList<>();
        for (Map.Entry<String, TransactionOutput> entry : localUTXOs.entrySet()) {
            if (blockchain.getMempoolSpent().contains(entry.getKey())) {
                continue;
            }
            // Find Private Key necessary to sign referenced UTXO
            byte[] pubKeyHash = entry.getValue().getPubKeyHash();
            KeyData key = this.getKeyByHash(pubKeyHash);
            String[] pointer = entry.getKey().split(":");
            byte[] refTx = Strings.toBytes(pointer[0]);
            int txOI = Integer.parseInt(pointer[1]);
            // Add Input to transaction
            TransactionInput input = new TransactionInput(refTx, txOI, key.pubKey);
            signingKeys.add(key.prvKey);
            transaction.add(input);
            totalValue -= entry.getValue().getValue();
            // Create change TransactionOutput if necessary
            if (totalValue < 0) {
                TransactionOutput change = new TransactionOutput(-1 * totalValue, this.getChangePubKey());
                transaction.add(change);
                break;
            } else if (totalValue == 0) {
                break;
            }
        }
        // Sign transaction
        transaction.sign(signingKeys);
        return transaction;
    }

    /**
     * @return The next unseen receive address from External keys. If there is
     * no unseen keys present, a new key is generated.
     */
    public String getReceiveAddress() {
        for (int i = 0; i < externalKeys.size(); i++) {
            KeyData key = externalKeys.get(i);
            if (!key.seen) {
                return key.address;
            }
        }
        return genExternalKey().address;
    }

    /**
     * @return The next unseen receive public key from External keys. If there
     * is no unseen keys present, a new key is generated. Same as
     * {@code getReceiveAddress()} except the pubKey component is returned
     * instead of the address component of the KeyData object.
     */
    public PublicKey getReceivePubKey() {
        for (int i = 0; i < externalKeys.size(); i++) {
            KeyData key = externalKeys.get(i);
            if (!key.seen) {
                return key.pubKey;
            }
        }
        return genExternalKey().pubKey;
    }

    /**
     * @return The next unseen receive pubKey from Internal keys. If there is no
     * unseen keys present, a new key is generated.
     */
    public PublicKey getChangePubKey() {
        for (int i = 0; i < internalKeys.size(); i++) {
            KeyData key = internalKeys.get(i);
            if (!key.seen) {
                return key.pubKey;
            }
        }
        return genInternalKey().pubKey;
    }

    /**
     * @return the wallet's mnemonic phrase.
     */
    public char[] getMnemonic() {
        return mnemonic;
    }

    /**
     * @return the wallet's derivation path.
     */
    public String getDerivationPath() {
        return derivationPath;
    }

    /**
     * @return the wallet's balance (does not update balance before getting
     * called).
     */
    public long getBalance() {
        return balance;
    }

    /**
     * Internal method used to find a suitable KeyData object to spend a
     * TransactionOutput.
     *
     * @param pubKeyHash the hash of a public key to find.
     * @return the KeyData object whose pubKeyHash matches. Returns {@code null}
     * if not found.
     */
    private KeyData getKeyByHash(byte[] pubKeyHash) {
        for (KeyData key : internalKeys) {
            if (Arrays.equals(key.pubKeyHash, pubKeyHash)) {
                return key;
            }
        }
        for (KeyData key : externalKeys) {
            if (Arrays.equals(key.pubKeyHash, pubKeyHash)) {
                return key;
            }
        }
        return null;
    }

    /**
     * Serializes a Wallet object into byte form. Format: mnemonicLength (4
     * bytes) || mnemonic (varies) || passphraseLength (4 bytes) || passphrase
     * (varies) || derivationLength (4 bytes) || derivation path (varies) ||
     * numKeysInternal (4 bytes) || seen/unseen (varies) || numKeysExternal (4
     * bytes) || seen/unseen (varies)
     *
     * @return a serialized representation of the Wallet.
     */
    public byte[] serialize() {
        byte[] mnemonicLength = ByteBuffer.allocate(4).putInt(mnemonic.length).array();
        byte[] passphraseLength = ByteBuffer.allocate(4).putInt(passphrase.length).array();
        byte[] derivationLength = ByteBuffer.allocate(4).putInt(derivationPath.length()).array();
        byte[] data = Bytes.concat(mnemonicLength, new String(mnemonic).getBytes(StandardCharsets.UTF_8));
        data = Bytes.concat(data, passphraseLength);
        data = Bytes.concat(data, new String(passphrase).getBytes(StandardCharsets.UTF_8));
        data = Bytes.concat(data, derivationLength);
        data = Bytes.concat(data, derivationPath.getBytes(StandardCharsets.UTF_8));
        int numKeysInternal = internalKeys.size();
        data = Bytes.concat(data, ByteBuffer.allocate(4).putInt(numKeysInternal).array());
        byte[] seenBytes = new byte[numKeysInternal];
        for (int i = 0; i < numKeysInternal; i++) {
            seenBytes[i] = (internalKeys.get(i).seen) ? (byte) 0x01 : (byte) 0x00;
        }
        data = Bytes.concat(data, seenBytes);
        int numKeysExternal = externalKeys.size();
        data = Bytes.concat(data, ByteBuffer.allocate(4).putInt(numKeysExternal).array());
        seenBytes = new byte[numKeysExternal];
        for (int i = 0; i < numKeysExternal; i++) {
            seenBytes[i] = (externalKeys.get(i).seen) ? (byte) 0x01 : (byte) 0x00;
        }
        return Bytes.concat(data, seenBytes);
    }

    /**
     * Deserializes a byte representation of a Wallet into an object.
     *
     * @param data the bytes of a serialized Wallet.
     * @return a Wallet object whose serialization is equivalent to the data
     * supplied.
     */
    public static Wallet deserialize(byte[] data) {
        int offset = 0;
        int mnemonicLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
        offset += 4;
        String mnemonic = new String(Arrays.copyOfRange(data, offset, offset + mnemonicLength),
                StandardCharsets.UTF_8);
        offset += mnemonicLength;
        int passphraseLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
        offset += 4;
        String passphrase = new String(Arrays.copyOfRange(data, offset, offset + passphraseLength),
                StandardCharsets.UTF_8);
        offset += passphraseLength;
        int derivationLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
        offset += 4;
        String derivationPath = new String(Arrays.copyOfRange(data, offset, offset + derivationLength),
                StandardCharsets.UTF_8);
        offset += derivationLength;
        Wallet wallet = new Wallet(mnemonic.toCharArray(), passphrase.toCharArray(), derivationPath);
        int numKeysInternal = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
        offset += 4;
        for (int i = wallet.internalKeys.size(); i < numKeysInternal; i++) {
            wallet.genInternalKey();
        }
        for (int i = 0; i < numKeysInternal; i++) {
            wallet.internalKeys.get(i).seen = (data[offset + i] == 0x01);
        }
        offset += numKeysInternal;
        int numKeysExternal = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
        offset += 4;
        for (int i = wallet.externalKeys.size(); i < numKeysExternal; i++) {
            wallet.genExternalKey();
        }
        for (int i = 0; i < numKeysExternal; i++) {
            wallet.externalKeys.get(i).seen = (data[offset + i] == 0x01);
        }
        offset += numKeysExternal;
        return wallet;
    }

    /**
     * @return the dump format of the Wallet object.
     */
    @Override
    public String toString() {
        String res = "";
        res += "Derivation Path: " + derivationPath + "\n";
        res += " Receiving Keys:\n";
        for (KeyData key : externalKeys) {
            res += "                 " + key.address + "\n";
        }
        res += "   Change Keys:\n";
        for (KeyData key : internalKeys) {
            res += "                 " + key.address + "\n";
        }
        res += " Related UTXOs:\n";
        for (TransactionOutput output : localUTXOs.values()) {
            res += output.toString();
        }
        return res;
    }
}
