package satokentestnet.struct;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import satokentestnet.client.Driver;
import satokentestnet.crypto.Hash;
import satokentestnet.util.Bytes;
import satokentestnet.util.Strings;

/**
 * A Block contains the information about transactions as well as a
 * Proof-of-Work showing that computation power was expended to find a hash
 * lower than the target difficulty. Blocks include: Previous block's hash,
 * timestamp when mined, difficulty target, Merkle tree of transactions, the
 * nonce used to find the block hash, and the height of the block.
 *
 * @author Carson Mullins
 */
public class Block {

    public static final byte[] magic = new byte[]{(byte) 0xF9, (byte) 0xBE,
        (byte) 0xB4, (byte) 0xD9};
    public static final byte[] rawGenesisBlock = Strings.toBytes("000000000000000000000000000000000000000000000000000000000000000000000fffffffffff04e001978be3d653c09077efd6f117832e5e4d794509f359cd7d15f2775ec8a7001fb39d0000016c071e039300000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00000008000000010000000000000001000000012a05f200c41c8412033f67b78e902cca17386e0b7bf6de19");
    private int nonce;
    private int height;
    private byte[] hash;
    private final byte[] prevHash, difficulty;
    private final long timestamp;
    private MerkleTree merkleTree;
    private final ArrayList<Transaction> transactions;

    /**
     * Default constructor of a block. A block is created with a reference to a
     * previous block, and since new blocks are created by the client itself the
     * Block object is known.
     *
     * @param prevBlock the previous Block used to calculate the hash of the
     * block.
     */
    public Block(Block prevBlock) {
        this.prevHash = prevBlock.hash;
        this.difficulty = Blockchain.getInstance().getDifficulty();
        this.height = Blockchain.getInstance().getHeight() + 1;
        this.timestamp = System.currentTimeMillis();
        this.transactions = new ArrayList<>();
        this.merkleTree = new MerkleTree(transactions);
    }

    /**
     * The constructor used for deserializing byte data into an object.
     *
     * @param prevHash the previous block's hash.
     * @param difficulty the target difficulty this block's Proof-of-work must
     * satisfy.
     * @param nonce the nonce used to calculate this block's hash below the
     * target difficulty.
     * @param timestamp the timestamp of when the block was mined.
     */
    public Block(byte[] prevHash, byte[] difficulty, int nonce, long timestamp) {
        this.prevHash = prevHash;
        this.difficulty = difficulty;
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.transactions = new ArrayList<>();
    }

    /**
     * Increments through nonce values until the block hashes to a value below
     * the target difficulty. If the nonce value overflows, the extranonce of
     * the Coinbase transaction is incremented.
     *
     * @param minerPubKey the public key of the miner used for block reward.
     */
    public void mine(PublicKey minerPubKey) {
        nonce = 0;
        int extraNonce = 0;
        transactions.add(Transaction.getCoinbase(height, minerPubKey, extraNonce));
        merkleTree.add(transactions.get(0));
        for (Transaction transaction : Blockchain.getInstance().getMempool()) {
            transactions.add(transaction);
            merkleTree.add(transaction);
        }
        BigInteger target = new BigInteger(1, Arrays.copyOf(difficulty, 32));
        BigInteger actual = new BigInteger(1, this.calculateHash());
        while (actual.compareTo(target) > 0) {
            if (nonce != 0 && nonce % 10000000 == 0) {
                Driver.cli.print(".");
            }
            if (nonce == 0xFFFFFFFF) {
                nonce = 0;
                extraNonce = -(~extraNonce);
                transactions.set(0, Transaction.getCoinbase(height, minerPubKey, extraNonce));
                merkleTree.updateFirst(transactions.get(0));
            } else {
                nonce = -(~nonce);
            }
            actual = new BigInteger(1, this.calculateHash());
        }
        this.hash = calculateHash();
    }

    /**
     * Calculates the block's hash. Format: previous hash || difficulty ||
     * Merkle root hash || nonce || timestamp
     *
     * @return the hash bytes of the block.
     */
    public byte[] calculateHash() {
        byte[] nonceBytes = ByteBuffer.allocate(4).putInt(nonce).array();
        byte[] timestampBytes = ByteBuffer.allocate(8).putLong(timestamp).array();
        byte[] data = Bytes.concat(prevHash, difficulty);
        data = Bytes.concat(data, merkleTree.getRoot().hash);
        data = Bytes.concat(data, nonceBytes);
        return Hash.sha256(Bytes.concat(data, timestampBytes));
    }

    /**
     * @return the list of transactions in the block.
     */
    public ArrayList<Transaction> getTransactions() {
        return transactions;
    }

    /**
     * @param index the index of the transaction to retrieve.
     * @return the transaction in the block at the specified index.
     */
    public Transaction getTransaction(int index) {
        return transactions.get(index);
    }

    /**
     * @return the timestamp of the block.
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * @return the hash bytes of the block.
     */
    public byte[] getHash() {
        return hash;
    }

    /**
     * @return the previous block's hash bytes.
     */
    public byte[] getPrevHash() {
        return prevHash;
    }

    /**
     * @return the difficulty of the block.
     */
    public byte[] getDifficulty() {
        return difficulty;
    }

    /**
     * Sets the height of the block.
     *
     * @param height the height of the block.
     */
    public void setHeight(int height) {
        this.height = height;
    }

    /**
     * @return the height of the block.
     */
    public int getHeight() {
        return height;
    }

    /**
     * Deserializes a byte representation of a Block into an object.
     *
     * @param data the bytes of a serialized Block.
     * @return a Block object whose serialization is equivalent to the data
     * supplied.
     */
    public static Block deserialize(byte[] data) {
        int offset = 0;
        byte[] prevHash = Arrays.copyOfRange(data, offset, offset += 32);
        byte[] difficulty = Arrays.copyOfRange(data, offset, offset += 8);
        // Expected Merkle Root
        byte[] expectedMerkleRoot = Arrays.copyOfRange(data, offset, offset += 32);
        int nonce = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
        long timestamp = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 8)).getLong();
        int numTransactions = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
        Block block = new Block(prevHash, difficulty, nonce, timestamp);
        for (int i = 0; i < numTransactions; i++) {
            ArrayList<TransactionInput> inputs = new ArrayList<>();
            ArrayList<TransactionOutput> outputs = new ArrayList<>();
            int numInputs = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
            for (int y = 0; y < numInputs; y++) {
                byte[] refTx = Arrays.copyOfRange(data, offset, offset += 32);
                int txOI = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
                int scriptLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
                byte[] scriptSig = Arrays.copyOfRange(data, offset, offset += scriptLength);
                TransactionInput input = new TransactionInput(refTx, txOI, scriptSig);
                inputs.add(input);
            }
            int numOutputs = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
            for (int y = 0; y < numOutputs; y++) {
                byte[] outputData = Arrays.copyOfRange(data, offset, offset += 28);
                TransactionOutput output = TransactionOutput.deserialize(outputData);
                outputs.add(output);
            }
            Transaction transaction = new Transaction(inputs, outputs);
            block.transactions.add(transaction);
        }
        block.merkleTree = new MerkleTree(block.transactions);
        if (!Arrays.equals(block.merkleTree.getRoot().hash, expectedMerkleRoot)) {
            System.out.println(" Block's Merkle Root does not match. Something went wrong, or block file has been tampered with.");
            System.exit(1);
        }
        block.hash = block.calculateHash();
        return block;
    }

    /**
     * Serializes a Block into byte form. Format: Data length (4 bytes) ||
     * previous hash (32 bytes) || difficulty (8 bytes) || Merkle root hash (32
     * bytes) || nonce (4 bytes) || timestamp (8 bytes) || numTransactions (4
     * bytes) || multiple serialized transactions (varies)
     *
     * @return a serialized representation of the Block.
     */
    public byte[] serialize() {
        byte[] nonceBytes = ByteBuffer.allocate(4).putInt(nonce).array();
        byte[] timestampBytes = ByteBuffer.allocate(8).putLong(timestamp).array();
        byte[] numTransactions = ByteBuffer.allocate(4).putInt(transactions.size()).array();
        byte[] data = Bytes.concat(prevHash, difficulty);
        data = Bytes.concat(data, merkleTree.getRoot().hash);
        data = Bytes.concat(data, nonceBytes);
        data = Bytes.concat(data, timestampBytes);
        data = Bytes.concat(data, numTransactions);
        for (Transaction transaction : transactions) {
            data = Bytes.concat(data, transaction.serialize());
        }
        byte[] dataLength = ByteBuffer.allocate(4).putInt(data.length).array();
        return Bytes.concat(dataLength, data);
    }

    /**
     * @return the dump format of a Block object.
     */
    @Override
    public String toString() {
        String res = "";
        res += "       Height: " + height + "\n";
        res += "         Hash: " + Bytes.toHex(hash) + "\n";
        res += "Previous Hash: " + Bytes.toHex(prevHash) + "\n";
        res += "  Merkle Root: " + Bytes.toHex(merkleTree.getRoot().hash) + "\n";
        res += "   Difficulty: " + Bytes.toHex(difficulty) + "\n";
        res += "    Timestamp: " + timestamp + "\n";
        res += "        Nonce: " + nonce + "\n";
        res += " Transactions:\n";
        for (Transaction transaction : transactions) {
            res += transaction + "\n\n";
        }
        return res;
    }
}
