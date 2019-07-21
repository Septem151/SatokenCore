package satokentestnet.struct;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.io.File;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import satokentestnet.client.Driver;
import satokentestnet.util.Bytes;
import satokentestnet.util.Strings;

/**
 * A Blockchain is a list of blocks whose hash contains the hash of the block
 * before it. This class also contains the Mempool (a list of transactions not
 * yet included in a block), the Chainstate (a map of unspent transaction
 * outputs in all blocks), as well as the business logic necessary for adding
 * and maintaining the blockchain structure.
 *
 * @author Carson Mullins
 */
public class Blockchain {

    private static Blockchain instance;
    public static final byte[] baseDifficulty = Strings.toBytes("00000FFFFFFFFFFF");
    private byte[] difficulty = baseDifficulty;
    public static final long baseReward = 5000000000l;
    public static final int halveningBlocks = 250;
    public static final int difficultyAdjustBlocks = 10;
    public static final long targetBlockTime = 10000;
    private ArrayList<Block> blocks;
    private final HashMap<String, TransactionOutput> chainstate;
    private final ArrayList<Transaction> mempool;
    private final HashMap<String, TransactionOutput> mempoolUTXOs;
    private final ArrayList<String> mempoolSpent;

    /**
     * Default constructor of a Blockchain. Simply creates new empty lists and
     * maps, the Blockchain itself is a singleton pattern.
     */
    private Blockchain() {
        blocks = new ArrayList<>();
        chainstate = new HashMap<>();
        mempool = new ArrayList<>();
        mempoolUTXOs = new HashMap<>();
        mempoolSpent = new ArrayList<>();
    }

    /**
     * @return the singleton Blockchain instance, instantiating if null.
     */
    public static Blockchain getInstance() {
        if (instance == null) {
            instance = new Blockchain();
        }
        return instance;
    }

    /**
     * Deserializes, verifies, and adds the genesis block to the blockchain.
     */
    public void mineGenesisBlock() {
        Block genesis = Block.deserialize(Block.rawGenesisBlock);
        genesis.setHeight(1);
        writeBlockToDisk(genesis);
    }

    /**
     * Verifies the header and all transactions in a block before adding it to
     * the list of blocks and updating Chainstate and Mempool.
     *
     * @param block the block to attempt to add.
     * @return whether the block was successfully verified and added.
     */
    public boolean addBlock(Block block) {
        if (blocks.isEmpty()) {
            byte[] data = block.serialize();
            data = Arrays.copyOfRange(data, 4, data.length);
            if (!Arrays.equals(Block.rawGenesisBlock, data)) {
                System.out.print(" Invalid Genesis block detected.");
                return false;
            }
            blocks.add(block);
            Transaction coinbase = block.getTransaction(0);
            TransactionOutput cbOut = coinbase.getOutput(0);
            String pointer = Strings.coinPointer(coinbase.getHash(), 0);
            chainstate.put(pointer, cbOut);
            return true;
        }
        HashMap<String, TransactionOutput> toState = new HashMap<>();
        ArrayList<String> remState = new ArrayList<>();
        ArrayList<Transaction> remMempool = new ArrayList<>();
        ArrayList<String> remMempoolSpent = new ArrayList<>();
        ArrayList<String> remMempoolUTXOs = new ArrayList<>();
        // Verify Header
        if (!Arrays.equals(getLastBlock().getHash(), block.getPrevHash())) {
            System.out.print(" Previous Hash does not match.");
            return false;
        }
        if (!Arrays.equals(block.getDifficulty(), difficulty)) {
            System.out.println(" Difficulty does not match the expected difficulty. \nBlock difficulty: " + Bytes.toHex(block.getDifficulty()));
            System.out.println("Expected Difficulty: " + Bytes.toHex(difficulty));
            return false;
        }
        // Verify Coinbase parameters
        ArrayList<Transaction> transactions = block.getTransactions();
        TransactionInput coinbaseIn = transactions.get(0).getInputs().get(0);
        if (!Arrays.equals(new byte[32], coinbaseIn.getRefTx()) || coinbaseIn.getTxOI() != -1
                || coinbaseIn.getScriptSig().length > 100) {
            System.out.print(" Invalid Coinbase input parameters.");
            return false;
        }
        TransactionOutput coinbaseOut = transactions.get(0).getOutput(0);
        if (coinbaseOut.getValue() > getBlockReward(blocks.size())) {
            System.out.print(" Invalid Coinbase output.");
            return false;
        }
        // Add coinbase output to chainstate
        String pointer = Strings.coinPointer(transactions.get(0).getHash(), 0);
        toState.put(pointer, coinbaseOut);
        // Remove transactions from mempool and add UTXOs to chainstate
        for (int i = 1; i < transactions.size(); i++) {
            Transaction transaction = transactions.get(i);
            // If we have not seen the transaction in mempool, verify it
            if (!mempool.contains(transaction) && !transaction.verify()) {
                System.out.print(" Invalid Transaction in block.");
                return false;
            }
            // Remove from mempool and any referenced UTXOs from chainstate
            remMempool.add(transactions.get(i));
            for (TransactionInput input : transaction.getInputs()) {
                pointer = Strings.coinPointer(input.getRefTx(), input.getTxOI());
                remState.add(pointer);
                remMempoolSpent.add(pointer);
            }
            // Add outputs to chainstate
            for (int y = 0; y < transaction.getOutputs().size(); y++) {
                pointer = Strings.coinPointer(transaction.getHash(), y);
                toState.put(pointer, transaction.getOutput(y));
                remMempoolUTXOs.add(pointer);
            }
        }
        for (Map.Entry<String, TransactionOutput> entry : toState.entrySet()) {
            chainstate.put(entry.getKey(), entry.getValue());
        }
        for (Transaction transaction : remMempool) {
            mempool.remove(transaction);
        }
        for (String point : remMempoolSpent) {
            mempoolSpent.remove(point);
        }
        for (String key : remState) {
            chainstate.remove(key);
        }
        for (String key : remMempoolUTXOs) {
            mempoolUTXOs.remove(key);
        }
        blocks.add(block);
        if (blocks.size() % difficultyAdjustBlocks == 0) {
            adjustDifficulty();
        }
        return true;
    }

    /**
     * Calls {@code addBlock(block)} and, if true, appends the block's
     * serialized data to the block file.
     *
     * @param block the block to verify, add to the blockchain, and write to
     * file.
     * @return whether the block was successfully verified and written to disk.
     */
    public boolean writeBlockToDisk(Block block) {
        if (!addBlock(block)) {
            return false;
        }
        try {
            File file = new File(Driver.blocksPath);
            if (!file.exists()) {
                System.out.println("Critical Error: Blocks file does not exist!");
                throw new IOException();
            }
            try (BufferedOutputStream bOut = new BufferedOutputStream(new FileOutputStream(file, true))) {
                bOut.write(Bytes.concat(Block.magic, block.serialize()));
            }
        } catch (IOException ex) {
            System.out.println("Critical Error: Could not save Blocks data.");
            System.exit(1);
        }
        return true;
    }

    /**
     * Calculates and assigns what the new difficulty should be based on how
     * close to {@value #targetBlockTime} milliseconds the average time of the
     * last {@value #difficultyAdjustBlocks} blocks was. If the difficulty would
     * be lowered by more than 15% or increased by more than 10%, then it is
     * clamped to those values.
     */
    private void adjustDifficulty() {
        Block firstBlock;
        if (blocks.size() == difficultyAdjustBlocks) {
            firstBlock = blocks.get(1);
        } else {
            firstBlock = blocks.get(blocks.size() - difficultyAdjustBlocks);
        }
        long actualTime = getLastBlock().getTimestamp() - firstBlock.getTimestamp();
        long averageTime = actualTime / difficultyAdjustBlocks;
        BigInteger adjust = BigInteger.valueOf(averageTime).multiply(BigInteger.valueOf(10000)).divide(BigInteger.valueOf(targetBlockTime));
        if (adjust.compareTo(BigInteger.valueOf(8500)) < 0) {
            adjust = BigInteger.valueOf(8500);
        } else if (adjust.compareTo(BigInteger.valueOf(11000)) > 0) {
            adjust = BigInteger.valueOf(11000);
        }
        BigInteger diff = new BigInteger(1, Arrays.copyOf(difficulty, 32));
        diff = diff.multiply(adjust).divide(BigInteger.valueOf(10000));
        difficulty = Strings.toBytes(String.format("%064X", diff));
        difficulty = Arrays.copyOfRange(difficulty, 0, 8);
    }

    /**
     * Replays however many blocks are left to update the Chainstate. If unable
     * to replay the blocks, the program will exit.
     *
     * @param highestKnownBlock the highest known block, and the block to start
     * replaying at.
     */
    private void catchupState(int highestKnownBlock) {
        System.out.print(" Replaying last " + (blocks.size() - highestKnownBlock) + " Blocks.");
        ArrayList<Block> replay = new ArrayList<>(blocks.subList(highestKnownBlock, blocks.size()));
        blocks = new ArrayList<>(blocks.subList(0, highestKnownBlock));
        difficulty = replay.get(0).getDifficulty();
        for (Block block : replay) {
            if (!addBlock(block)) {
                System.out.println(" Failed to replay chainstate.");
                System.exit(1);
            }
        }
    }

    /**
     * Calculates the block reward at the given block height.
     *
     * @param height the height to find block reward at.
     * @return the block reward.
     */
    public long getBlockReward(int height) {
        long reward = baseReward;
        int halvenings = height / halveningBlocks;
        for (int i = 0; i < halvenings; i++) {
            reward /= 2;
        }
        return reward;
    }

    /**
     * Finds all confirmed and unconfirmed unspent outputs relevant to the given
     * public key hash.
     *
     * @param pubKeyHash the public key hash to search for.
     * @return the map of all relevant UTXOs.
     */
    public HashMap<String, TransactionOutput> getUTXOs(byte[] pubKeyHash) {
        HashMap<String, TransactionOutput> UTXOset = new HashMap<>();
        for (Map.Entry<String, TransactionOutput> entry : chainstate.entrySet()) {
            if (Arrays.equals(entry.getValue().getPubKeyHash(), pubKeyHash)) {
                UTXOset.put(entry.getKey(), entry.getValue());
            }
        }
        for (Map.Entry<String, TransactionOutput> entry : mempoolUTXOs.entrySet()) {
            if (Arrays.equals(entry.getValue().getPubKeyHash(), pubKeyHash)) {
                UTXOset.put(entry.getKey(), entry.getValue());
            }
        }
        return UTXOset;
    }

    /**
     * @param pointer the coin pointer to find in the spent Mempool collection.
     * @return whether the specified coin is spent.
     */
    public boolean isSpentUTXO(String pointer) {
        return mempoolSpent.contains(pointer);
    }

    /**
     * @return the Chainstate of the blockchain.
     */
    public HashMap<String, TransactionOutput> getChainstate() {
        return chainstate;
    }

    /**
     * @return the Mempool of the blockchain.
     */
    public ArrayList<Transaction> getMempool() {
        return mempool;
    }

    /**
     * @return the list of spent coin pointers in the Mempool.
     */
    public ArrayList<String> getMempoolSpent() {
        return mempoolSpent;
    }

    /**
     * @return the map of unconfirmed unspent outputs.
     */
    public HashMap<String, TransactionOutput> getMempoolUTXOs() {
        return mempoolUTXOs;
    }

    /**
     * @return the height of the blockchain.
     */
    public int getHeight() {
        return blocks.size();
    }

    /**
     * @return the current difficulty of the blockchain.
     */
    public byte[] getDifficulty() {
        return difficulty;
    }

    /**
     * @return the latest block of the blockchain.
     */
    public Block getLastBlock() {
        return blocks.get(blocks.size() - 1);
    }

    /**
     * Deserializes the given data into the respective blocks and adds them to
     * the blockchain.
     *
     * @param data the data to Deserialize. If the data does not match valid
     * block format, the program is exited.
     */
    public void deserializeBlocks(byte[] data) {
        blocks.clear();
        int offset = 0;
        if (data.length < 4) {
            return;
        }
        while (offset < data.length) {
            byte[] magic = Arrays.copyOfRange(data, offset, offset += 4);
            if (!Arrays.equals(Block.magic, magic)) {
                System.out.println("Block data is invalid. Magic bytes do not match.");
                System.exit(1);
            }
            int dataLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
            byte[] blockData = Arrays.copyOfRange(data, offset, offset += dataLength);
            Block block = Block.deserialize(blockData);
            if (blocks.size() > 0 && !Arrays.equals(block.getPrevHash(), blocks.get(blocks.size() - 1).getHash())) {
                System.out.println(
                        " Block's Previous Hash does not match the actual block's previous hash. Something went wrong or the block data was tampered with.");
                System.exit(1);
            }
            block.setHeight(blocks.size() + 1);
            addBlock(block);
        }
    }

    /**
     * Deserializes the given data into the respective pointers and outputs,
     * then adds them to the Chainstate. If the Chainstate is not up-to-date
     * with the latest block, the missing blocks are replayed/reverified in
     * order to catch up the Chainstate.
     *
     * @param data the data to Deserialize. If the data does not match valid
     * Chainstate format, the program is exited.
     */
    public void deserializeState(byte[] data) {
        boolean catchup = false;
        int offset = 0;
        if (data.length <= 4) {
            if (!blocks.isEmpty()) {
                catchupState(0);
                return;
            }
        }
        int highestKnownBlock = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
        catchup = (highestKnownBlock != blocks.size());
        while (offset < data.length) {
            byte[] txHash = Arrays.copyOfRange(data, offset, offset += 32);
            int txOI = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset += 4)).getInt();
            byte[] outputData = Arrays.copyOfRange(data, offset, offset += 28);
            TransactionOutput output = TransactionOutput.deserialize(outputData);
            chainstate.put(Strings.coinPointer(txHash, txOI), output);
        }
        if (catchup) {
            catchupState(highestKnownBlock);
        }
    }

    /**
     * Serializes the Chainstate into byte form. Format: Block height (4 bytes)
     * || multiple: transaction hash (32 bytes) || output index (4 bytes)
     *
     * @return a serialized representation of the Chainstate.
     */
    public byte[] serializeState() {
        byte[] data = ByteBuffer.allocate(4).putInt(getHeight()).array();
        for (Map.Entry<String, TransactionOutput> entry : chainstate.entrySet()) {
            String[] pointer = entry.getKey().split(":");
            data = Bytes.concat(data, Strings.toBytes(pointer[0]));
            data = Bytes.concat(data, ByteBuffer.allocate(4).putInt(Integer.parseInt(pointer[1])).array());
            data = Bytes.concat(data, entry.getValue().serialize());
        }
        return data;
    }

    /**
     * @return a String representation of the Chainstate.
     */
    public String chainstateString() {
        String res = "";
        for (Map.Entry<String, TransactionOutput> entry : chainstate.entrySet()) {
            String[] pointer = entry.getKey().split(":");
            res += "Transaction: " + pointer[0] + "\n";
            res += "     Output: " + pointer[1] + "\n";
            res += entry.getValue().toString() + "\n\n";
        }
        return res;
    }

    /**
     * @return a String representation of the Mempool.
     */
    public String mempoolString() {
        String res = "";
        for (int i = 0; i < mempool.size(); i++) {
            res += "Transaction " + i + ":\n" + mempool.get(i).toString() + "\n\n";
        }
        return res;
    }

    /**
     * @return the dump format of the Blockchain.
     */
    @Override
    public String toString() {
        String res = "";
        int quantity = 3;
        if (blocks.size() < quantity) {
            quantity = blocks.size();
        }
        for (int i = blocks.size() - quantity; i < blocks.size(); i++) {
            res += blocks.get(i).toString() + "\n";
        }
        return res;
    }

}
