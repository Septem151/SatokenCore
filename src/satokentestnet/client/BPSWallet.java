package satokentestnet.client;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.KeyPair;
import satokentestnet.crypto.DataCipher;
import satokentestnet.crypto.Hash;
import satokentestnet.crypto.InvalidPasswordException;
import satokentestnet.crypto.KeyDerivation;
import satokentestnet.struct.Address;
import satokentestnet.struct.Blockchain;
import satokentestnet.struct.Transaction;
import satokentestnet.struct.TransactionInput;
import satokentestnet.struct.TransactionOutput;
import satokentestnet.util.Bytes;
import satokentestnet.util.Keys;
import satokentestnet.util.Strings;

/**
 * Better Privacy and Storage (BPS) Wallet What are the issues with the current
 * Wallet class? (1) Large amounts of derived keys to search through causes slow
 * loading times because each address must be derived and checked linearly
 * incase funds have been received to a previously derived address. Deriving an
 * address from a private key is an expensive operation (See {@link satokentestnet.crypto.ScalarMultiply#scalmult(java.security.spec.ECPoint, java.math.BigInteger)
 * }). (2) Private keys are exposed in memory for the duration of the object's
 * existence. This data persists in a {@link satokentestnet.struct.KeyData}
 * object stored in an ArrayList. (3) Seed is exposed in memory for the duration
 * of the object's existence. This data persists because it is necessary to
 * derive keys.
 *
 * How should these issues be handled? (1) Serializing public key hashes will
 * allow the wallet to choose which indeces need to be derived. The tradeoff of
 * decreased loading times for increased storage space is favorable, as the
 * storage necessary is negligible. This proposal increases the serialized data
 * by 4 + 21*(num hashes) bytes; 4 bytes representing num hashes and 21 bytes
 * for each hash. Keys only need to be derived when absolutely necessary. (2)
 * Signing transactions and deriving new public keys temporarily exposes private
 * keys in memory rather than persisting for the object's existence. (3) The
 * extended private keys for receiving/change addresses must be known, and is
 * technically the only private information that is necessary to store. The
 * user's wallet file password (the derived AES key) will run through an HMAC
 * with a new salt to derive a new AES key which will encrypt the extended
 * private keys until a new private key needs to be derived. This provides
 * obfuscation of the extended private key data, and prevents the need for the
 * wallet file password to persist in memory.
 *
 * What new issues will be introduced? (1) Signing transactions and generating
 * new receive/change addresses will take an insignificantly longer amount of
 * time (a few milliseconds) per input. (2) Storage space increases 20 bytes
 * more per key than before.
 *
 * Dependencies: {@link satokentestnet.struct.Address} and {@link Driver}
 *
 * @author Carson Mullins
 */
public class BPSWallet {

    public final byte[] version = ByteBuffer.allocate(4).putInt(1).array();
    public static final String defaultDerivation = "m/44'/0'/0'";
    public static final int numLookAhead = 10;

    private long balance;
    private final HashMap<String, TransactionOutput> localUTXOs;

    private final String derivation;
    private byte[] ownerSalt, ownerPubKey, encryptionFlag;
    private final byte[] xprvsEncrypted;
    private byte[] xpubExternal, xpubInternal;
    private final ArrayList<Address> externalAddresses, internalAddresses;

    /**
     * Constructor that derives a mnemonic phrase from a cryptographically
     * secure entropy source from which keys are derived. Keys are continuously
     * derived until there have been {@value #numLookAhead} unused keys found in
     * a row.
     *
     * @param password the password to encrypt both the wallet file and extended
     * private keys. keys with.
     * @param passphrase the extra bits of entropy used as salt for deriving a
     * seed.
     * @param derivation the hierarchical path to take when deriving addresses.
     */
    public BPSWallet(char[] password, char[] passphrase, String derivation) {
        System.out.print("Creating wallet.");
        externalAddresses = new ArrayList<>();
        internalAddresses = new ArrayList<>();
        localUTXOs = new HashMap<>();
        this.derivation = derivation;
        char[] mnemonic = generateMnemonic();
        xprvsEncrypted = DataCipher.encryptData(initExtendedKeys(mnemonic, passphrase), password);
        initAddresses();
        genUserKey(password);
        System.out.println(" OK\n");
        System.out.println("Take note of your Recovery Seed:");
        System.out.println("WARNING! THIS WILL NOT BE SHOWN AGAIN.\n");
        System.out.println(new String(mnemonic) + "\n");
    }

    /**
     * Constructor for recovering a new BPSWallet with a given mnemonic phrase.
     *
     * @param password the password to encrypt both the wallet file and extended
     * private keys. keys with.
     * @param passphrase the passphrase the wallet will create a seed from.
     * @param mnemonic the mnemonic the wallet will create a seed from.
     * @param derivation the derivation path that the keys will be derived from.
     */
    public BPSWallet(char[] password, char[] passphrase, char[] mnemonic, String derivation) {
        System.out.print("Recovering wallet.");
        externalAddresses = new ArrayList<>();
        internalAddresses = new ArrayList<>();
        localUTXOs = new HashMap<>();
        this.derivation = derivation;
        xprvsEncrypted = DataCipher.encryptData(initExtendedKeys(mnemonic, passphrase), password);
        initAddresses();
        genUserKey(password);
        System.out.println(" OK\n");
    }

    /**
     * Constructor used for decrypting a BPSWallet encrypted file data.
     *
     * @param encryptedData the BPSWallet's encrypted file data.
     * @param password the file's password.
     * @throws InvalidPasswordException if the password supplied does not match
     * the file's password.
     */
    public BPSWallet(byte[] encryptedData, char[] password) throws InvalidPasswordException {
        byte[] data = DataCipher.ECIESdecrypt(encryptedData, password);
        System.out.print("Loading Wallet.");
        externalAddresses = new ArrayList<>();
        internalAddresses = new ArrayList<>();
        localUTXOs = new HashMap<>();
        int offset = 0;
        int derivLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
        derivation = new String(Arrays.copyOfRange(data, offset, offset += derivLength));
        xpubExternal = Arrays.copyOfRange(data, offset, offset += 65);
        xpubInternal = Arrays.copyOfRange(data, offset, offset += 65);
        int numExternal = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
        for (int i = 0; i < numExternal; i++) {
            externalAddresses.add(Address.deserialize(Arrays.copyOfRange(data, offset, offset += 21)));
        }
        int numInternal = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
        for (int i = 0; i < numInternal; i++) {
            internalAddresses.add(Address.deserialize(Arrays.copyOfRange(data, offset, offset += 21)));
        }
        xprvsEncrypted = Arrays.copyOfRange(data, offset, data.length);
        genUserKey(password);
        System.out.println(" OK\n");
    }

    /**
     * Converts a LegacyWallet's encrypted file data into a BPSWallet object.
     *
     * @param encryptedData the LegacyWallet's encrypted file data.
     * @param password the file's password.
     * @return a BPSWallet object whose data matches that of the LegacyWallet.
     * @throws InvalidPasswordException if the password supplied does not match
     * the file's password.
     */
    public static BPSWallet convertLegacyToBPS(byte[] encryptedData, char[] password) throws InvalidPasswordException {
        byte[] data = DataCipher.decryptData(encryptedData, password);
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
        int numKeysInternal = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
        offset += 4;
        boolean[] seenInternal = new boolean[numKeysInternal];
        System.out.println("Num internal: " + numKeysInternal);
        for (int i = 0; i < seenInternal.length; i++) {
            seenInternal[i] = (data[offset++] == 0x01);
        }
        int numKeysExternal = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
        offset += 4;
        boolean[] seenExternal = new boolean[numKeysExternal];
        System.out.println("Num external: " + numKeysExternal);
        for (int i = 0; i < seenExternal.length; i++) {
            seenExternal[i] = (data[offset++] == 0x01);
        }
        BPSWallet wallet = new BPSWallet(password, passphrase.toCharArray(), mnemonic.toCharArray(), derivationPath);
        for (int i = wallet.externalAddresses.size(); i < seenExternal.length; i++) {
            wallet.genExternalKey();
            if (seenExternal[i]) {
                wallet.externalAddresses.get(i).seen();
            }
        }
        for (int i = wallet.internalAddresses.size(); i < seenInternal.length; i++) {
            wallet.genInternalKey();
            if (seenInternal[i]) {
                wallet.internalAddresses.get(i).seen();
            }
        }
        return wallet;
    }

    /**
     * Attempts to construct a new Transaction that has the given outputs, and
     * attempts to decrypt {@code xprvsEncrypted} to sign the transaction.
     *
     * @param outputs the outputs to include in the transaction.
     * @param password the password used to decrypt {@code xprvsEncrypted}.
     * @return the signed Transaction with the given outputs + change (if
     * needed) and inputs to match. If the wallet does not have enough balance,
     * {@code null} is returned.
     * @throws InvalidPasswordException if the password provided does not match
     * the password to decrypt {@code xprvsEncrypted}.
     */
    public Transaction buildTransaction(ArrayList<TransactionOutput> outputs, char[] password) throws InvalidPasswordException {
        Blockchain blockchain = Blockchain.getInstance();
        long totalValue = 0;
        Transaction transaction = new Transaction();
        // Add Outputs to transaction
        for (TransactionOutput output : outputs) {
            transaction.add(output);
            totalValue += output.getValue();
        }
        // Check if wallet balance is enough
        updateBalance();
        if (totalValue > balance) {
            System.out.println("\nNot enough funds to create Transaction.\n");
            return null;
        }
        // Create Inputs from local UTXOs
        byte[] xprvKeys = DataCipher.decryptData(xprvsEncrypted, password);
        byte[] xprvExternal = Arrays.copyOfRange(xprvKeys, 0, 64);
        byte[] xprvInternal = Arrays.copyOfRange(xprvKeys, 64, 128);
        ArrayList<PrivateKey> signingKeys = new ArrayList<>();
        for (Map.Entry<String, TransactionOutput> entry : localUTXOs.entrySet()) {
            if (blockchain.getMempoolSpent().contains(entry.getKey())) {
                continue;
            }
            // Find Private Key necessary to sign referenced UTXO
            byte[] pubKeyHash = entry.getValue().getPubKeyHash();
            int prvKeyIndex = externalAddresses.indexOf(new Address(pubKeyHash));
            byte[] prvKeyBytes;
            if (prvKeyIndex == -1) {
                prvKeyIndex = internalAddresses.indexOf(new Address(pubKeyHash));
                prvKeyBytes = KeyDerivation.CKDpriv(xprvInternal, prvKeyIndex, false);
            } else {
                prvKeyBytes = KeyDerivation.CKDpriv(xprvExternal, prvKeyIndex, false);
            }
            prvKeyBytes = Arrays.copyOfRange(prvKeyBytes, 0, 32);
            KeyPair keyPair = Keys.toKeyPair(prvKeyBytes);
            signingKeys.add(keyPair.getPrivate());
            String[] pointer = entry.getKey().split(":");
            byte[] refTx = Strings.toBytes(pointer[0]);
            int txOI = Integer.parseInt(pointer[1]);
            // Add Input to transaction
            TransactionInput input = new TransactionInput(refTx, txOI, keyPair.getPublic());
            transaction.add(input);
            totalValue -= entry.getValue().getValue();
            // Create change TransactionOutput if necessary
            if (totalValue < 0) {
                TransactionOutput change = new TransactionOutput(-1 * totalValue, this.getChangePubKeyHash());
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
     * Updates the wallet's balance by iterating through all derived addresses
     * and checking if there are any related UTXOs in the Blockchain's
     * Chainstate and Mempool. TODO: Find a way to know if there is unconfirmed
     * balance.
     */
    public void updateBalance() {
        balance = 0;
        localUTXOs.clear();
        HashMap<String, TransactionOutput> UTXOset;
        for (Address address : internalAddresses) {
            UTXOset = Blockchain.getInstance().getUTXOs(address.getPubKeyHash());
            if (UTXOset.isEmpty()) {
                continue;
            }
            address.seen();
            for (Map.Entry<String, TransactionOutput> entry : UTXOset.entrySet()) {
                if (Blockchain.getInstance().isSpentUTXO(entry.getKey())) {
                    continue;
                }
                localUTXOs.put(entry.getKey(), entry.getValue());
                balance += entry.getValue().getValue();
            }
        }
        for (Address address : externalAddresses) {
            UTXOset = Blockchain.getInstance().getUTXOs(address.getPubKeyHash());
            if (UTXOset.isEmpty()) {
                continue;
            }
            address.seen();
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
     * Formats the wallet's balance in the format: 0.00000000 STK. NOTE: Does
     * NOT update the wallet's balance.
     *
     * @return the formatted balance as a String.
     */
    public String printBalance() {
        String balStr = String.format("%09d", balance);
        balStr = balStr.substring(0, balStr.length() - 8) + "." + balStr.substring(balStr.length() - 8) + " STK";
        return balStr;
    }

    /**
     * Generates fresh addresses until {@value numLookAhead} keys in a row have
     * been discovered that are not seen before in the blockchain. Note: This
     * only checks for keys that show up in the UTXO set. Recovering a wallet
     * does not replay all blocks to check for used keys.
     */
    private void initAddresses() {
        int count = 0;
        while (count < numLookAhead) {
            Address key = genExternalKey();
            if (!Blockchain.getInstance().getUTXOs(key.getPubKeyHash()).isEmpty()) {
                key.seen();
                count = 0;
            } else {
                count++;
            }
        }
        count = 0;
        while (count < numLookAhead) {
            Address key = genInternalKey();
            if (!Blockchain.getInstance().getUTXOs(key.getPubKeyHash()).isEmpty()) {
                key.seen();
                count = 0;
            } else {
                count++;
            }
        }
    }

    /**
     * Derives the extended private and public keys for both External level and
     * Internal level.
     *
     * @param mnemonic the seed phrase to use for deriving the BIP32 Root.
     * @param passphrase the passphrase to use for deriving the BIP32 Root (may
     * be blank).
     * @return xprvExternal || xprvInternal
     */
    private byte[] initExtendedKeys(char[] mnemonic, char[] passphrase) {
        byte[] seed = Hash.PBKDF2(mnemonic, ("mnemonic" + new String(passphrase)).getBytes(StandardCharsets.UTF_8), 2048,
                64 * 8);
        byte[] xkey = Hash.hmac("Bitcoin seed".getBytes(StandardCharsets.UTF_8), seed);
        String[] levels = derivation.split("/");
        for (int i = 1; i < levels.length; i++) {
            boolean hardened = false;
            int index = -1;
            try {
                if (levels[i].contains("'")) {
                    Integer.parseInt(levels[i].substring(0, levels[i].length() - 1));
                    hardened = true;
                } else {
                    Integer.parseInt(levels[i]);
                }
            } catch (NumberFormatException ex) {
                System.out.println("Invalid Derivation Path, unable to proceed.");
                System.exit(1);
            }
            xkey = KeyDerivation.CKDpriv(xkey, index, hardened);
        }
        xpubExternal = KeyDerivation.NCKDpriv(xkey, 0, false);
        xpubInternal = KeyDerivation.NCKDpriv(xkey, 1, false);
        byte[] xprvExternal = KeyDerivation.CKDpriv(xkey, 0, false);
        byte[] xprvInternal = KeyDerivation.CKDpriv(xkey, 1, false);
        return Bytes.concat(xprvExternal, xprvInternal);
    }

    /**
     * Generates a 12-word mnemonic phrase using 16 bytes (128 bits) of entropy
     * from a cryptographically secure pseudo-random number generator.
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
     * Generates a random salt value and derives the owner's public key for use
     * in ECIES encryption.
     *
     * @param password the password used to encrypt the wallet with ECIES.
     */
    private void genUserKey(char[] password) {
        encryptionFlag = new byte[]{(byte) (password.length == 0 ? 0x00 : 0x01)};
        ownerSalt = DataCipher.generateSalt();
        ownerPubKey = KeyDerivation.PBKDF2toECIES(password, ownerSalt);
    }

    /**
     * Generates a new address for receiving coins (an externally facing
     * address).
     *
     * @return the Address object generated.
     */
    public Address genExternalKey() {
        byte[] xkey = KeyDerivation.CKDpub(xpubExternal, externalAddresses.size());
        byte[] pubKey = Arrays.copyOfRange(xkey, 0, 33);
        byte[] pubKeyHash = Hash.hash160(pubKey);
        Address address = new Address(pubKeyHash);
        externalAddresses.add(address);
        return address;
    }

    /**
     * Generates a new address for change in transactions created by this wallet
     * (an internally facing address).
     *
     * @return the Address object generated.
     */
    public Address genInternalKey() {
        byte[] xkey = KeyDerivation.CKDpub(xpubInternal, internalAddresses.size());
        byte[] pubKey = Arrays.copyOfRange(xkey, 0, 33);
        byte[] pubKeyHash = Hash.hash160(pubKey);
        Address address = new Address(pubKeyHash);
        internalAddresses.add(address);
        return address;
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
     * Serializes the information of this wallet. Information includes:
     *
     * derivLength || derivation || xpubExternal || xpubInternal || num external
     * keys || (isSeen || address) * num external keys || num internal keys ||
     * (isSeen || address) * num internal keys || xprvsEncrypted
     *
     * @return the serialized data for this wallet.
     */
    public byte[] serialize() {
        byte[] derivBytes = derivation.getBytes(StandardCharsets.UTF_8);
        byte[] derivLength = ByteBuffer.allocate(4).putInt(derivBytes.length).array();
        byte[] data = Bytes.concat(derivLength, derivBytes);
        data = Bytes.concat(data, xpubExternal);
        data = Bytes.concat(data, xpubInternal);
        byte[] numExternal = ByteBuffer.allocate(4).putInt(externalAddresses.size()).array();
        byte[] numInternal = ByteBuffer.allocate(4).putInt(internalAddresses.size()).array();
        data = Bytes.concat(data, numExternal);
        for (Address address : externalAddresses) {
            data = Bytes.concat(data, address.serialize());
        }
        data = Bytes.concat(data, numInternal);
        for (Address address : internalAddresses) {
            data = Bytes.concat(data, address.serialize());
        }
        return Bytes.concat(data, xprvsEncrypted);
    }

    /**
     * @return The next unseen receive pubKeyHash from Internal addresses. If
     * there is no unseen addresses present, a new key is generated.
     */
    public byte[] getChangePubKeyHash() {
        for (Address address : internalAddresses) {
            if (!address.isSeen()) {
                return address.getPubKeyHash();
            }
        }
        return genInternalKey().getPubKeyHash();
    }

    /**
     * @return The next unseen receive pubKeyHash from External addresses. If
     * there is no unseen addresses present, a new key is generated.
     */
    public byte[] getReceivePubKeyHash() {
        for (Address address : externalAddresses) {
            if (!address.isSeen()) {
                return address.getPubKeyHash();
            }
        }
        return genExternalKey().getPubKeyHash();
    }

    /**
     * @return The next unseen receive address from External addresses. If there
     * is no unseen addresses present, a new key is generated.
     */
    public String getReceiveAddress() {
        for (Address address : externalAddresses) {
            if (!address.isSeen()) {
                return address.getAddress();
            }
        }
        return genExternalKey().getAddress();
    }

    /**
     * @return the wallet's derivation path.
     */
    public String getDerivation() {
        return derivation;
    }

    /**
     * @return the owner's public key used to derive the symmetric key in ECIES
     * encryption.
     */
    public byte[] getOwnerPubKey() {
        return ownerPubKey;
    }

    /**
     * @return the salt used to generate the password's public key for ECIES
     * encryption.
     */
    public byte[] getOwnerSalt() {
        return ownerSalt;
    }

    /**
     * @return the wallet's Encryption Flag (0x01 for true, 0x00 for false).
     */
    public byte[] getEncryptionFlag() {
        return encryptionFlag;
    }

    /**
     * @return the dump format of the BPSWallet object.
     */
    @Override
    public String toString() {
        String res = "";
        res += "Derivation Path: " + derivation + "\n";
        res += " Receiving Keys:\n";
        for (Address address : externalAddresses) {
            res += "                 " + address.getAddress() + "\n";
        }
        res += "   Change Keys:\n";
        for (Address address : internalAddresses) {
            res += "                 " + address.getAddress() + "\n";
        }
        res += " Related UTXOs:\n";
        for (TransactionOutput output : localUTXOs.values()) {
            res += output.toString();
        }
        return res;
    }
}
