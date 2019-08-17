package satokentestnet.struct;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Arrays;
import java.util.Map;
import satokentestnet.crypto.Hash;
import satokentestnet.util.Bytes;
import satokentestnet.util.Strings;

/**
 * A Transaction contains input(s) and output(s). Each input references a
 * previous transaction's output, and each output assigns ownership of coins to
 * recipients. A transaction can be identified by the hash of its contents
 * (double SHA-256), which prevents tampering of the inputs and outputs.
 *
 * @author Carson Mullins
 */
public class Transaction {

    private final ArrayList<TransactionInput> inputs;
    private final ArrayList<TransactionOutput> outputs;
    private byte[] hash;

    /**
     * Default constructor of a Transaction. Inputs and outputs must be added,
     * as a transaction is not considered valid if it has less than 1 input or
     * less than 1 output.
     */
    public Transaction() {
        inputs = new ArrayList<>();
        outputs = new ArrayList<>();
        hash = new byte[32];
    }

    /**
     * Secondary constructor used when deserializing a block from file for
     * faster performance, as the standard way of adding inputs and outputs to a
     * transaction includes a hash of the data each time one is added. This
     * allows for a transaction to be created with multiple inputs and outputs
     * and only one hash operation.
     *
     * @param inputs the inputs of the transaction.
     * @param outputs the outputs of the transaction.
     */
    public Transaction(ArrayList<TransactionInput> inputs, ArrayList<TransactionOutput> outputs) {
        this.inputs = inputs;
        this.outputs = outputs;
        hash = this.calculateHash();
    }

    /**
     * Allows for consistent creation of Coinbase transactions.
     *
     * @param height the block height this transaction will be included in.
     * @param minerPubKeyHash the PubKeyHash of the block's miner.
     * @param extraNonce the extranonce of the mined block.
     * @return a Transaction whose input matches the expected Coinbase
     * requirements and whose output is the expected block reward given to the
     * miner.
     */
    public static Transaction getCoinbase(int height, byte[] minerPubKeyHash, int extraNonce) {
        Transaction coinbase = new Transaction();
        TransactionInput input = TransactionInput.getCoinbaseInput(height, extraNonce);
        long blockReward = (height != 1) ? Blockchain.getInstance().getBlockReward(height) : Blockchain.baseReward;
        TransactionOutput output = new TransactionOutput(blockReward, minerPubKeyHash);

        coinbase.add(input, output);
        coinbase.hash = coinbase.calculateHash();
        return coinbase;
    }

    /**
     * Adds the given inputs and outputs to the transaction. After all are
     * added, the hash of the transaction is calculated.
     *
     * @param oSet the input(s)/output(s) to add.
     */
    public void add(Object... oSet) {
        for (Object o : oSet) {
            if (o.getClass() == TransactionInput.class) {
                inputs.add((TransactionInput) o);
            } else if (o.getClass() == TransactionOutput.class) {
                outputs.add((TransactionOutput) o);
            }
        }
        hash = calculateHash();
    }

    /**
     * Generates the signatures of the inputs of the transaction.
     *
     * @param privateKeys the signing keys for all inputs of the transaction.
     */
    public void sign(ArrayList<PrivateKey> privateKeys) {
        if (privateKeys.size() != inputs.size()) {
            System.out.println("Critical Error: Not enough signing keys present for the transaction to be signed.");
            System.exit(1);
        }
        byte[] data = calculateHash();
        for (int i = 0; i < inputs.size(); i++) {
            byte[] sig = Hash.sign(data, privateKeys.get(i));
            inputs.get(i).setSig(sig);
        }
        hash = calculateHash();
    }

    /**
     * Verifies that a transaction has only valid inputs and that the outputs do
     * not total up in value greater than the inputs. If valid, this method adds
     * the transaction to the blockchain mempool.
     *
     * @return whether the transaction is valid.
     */
    public boolean verify() {
        Blockchain blockchain = Blockchain.getInstance();
        long valueOut = 0;
        ArrayList<byte[]> signatures = new ArrayList<>();
        ArrayList<String> spent = new ArrayList<>();
        HashMap<String, TransactionOutput> added = new HashMap<>();
        for (TransactionInput input : inputs) {
            // Check if input spends an existing output that has not already been spent in a
            // previous transaction from mempool
            String pointer = Strings.coinPointer(input.getRefTx(), input.getTxOI());
            if (!blockchain.getChainstate().containsKey(pointer) && !blockchain.getMempoolUTXOs().containsKey(pointer)) {
                System.out.print(" Input does not exist in chainstate or unconfirmed chainstate.");
                return false;
            }
            if (blockchain.getMempoolSpent().contains(pointer)) {
                System.out.print(" Double Spend in Transaction.");
                return false;
            }
            spent.add(pointer);
            if (blockchain.getChainstate().containsKey(pointer)) {
                valueOut += blockchain.getChainstate().get(pointer).getValue();
            } else {
                valueOut += blockchain.getMempoolUTXOs().get(pointer).getValue();
            }
            byte[] sig = input.getSig();
            signatures.add(sig);
            input.clearSig();
        }
        byte[] data = this.calculateHash();
        for (int i = 0; i < inputs.size(); i++) {
            // Find referenced UTXO from chainstate/unconfirmed chainstate
            TransactionInput input = inputs.get(i);
            String pointer = Strings.coinPointer(input.getRefTx(), input.getTxOI());
            TransactionOutput refOutput;
            if (blockchain.getChainstate().containsKey(pointer)) {
                refOutput = blockchain.getChainstate().get(pointer);
            } else {
                refOutput = blockchain.getMempoolUTXOs().get(pointer);
            }
            // Verify Public Key of input hashes to PubKeyHash of output
            byte[] expectedHash = refOutput.getPubKeyHash();
            if (!Arrays.equals(input.getPubKeyHash(), expectedHash)) {
                System.out.print(" PubKeyHash does not match.");
                return false;
            }
            // Verify signature of input
            if (!Hash.verify(data, signatures.get(i), input.getPubKey())) {
                System.out.print(" Signature did not validate.");
                return false;
            }
            input.setSig(signatures.get(i));
        }
        hash = calculateHash();
        // Iterate through Outputs and add to mempool UTXOs
        for (int i = 0; i < outputs.size(); i++) {
            String pointer = Strings.coinPointer(hash, i);
            added.put(pointer, outputs.get(i));
            valueOut -= outputs.get(i).getValue();
        }
        // Check if outputs spend more than inputs
        if (valueOut < 0) {
            System.out.print(" Transaction output value > input value.");
            return false;
        }
        // Update mempool variables, Transaction is verified
        blockchain.getMempool().add(this);
        for (String pointer : spent) {
            blockchain.getMempoolSpent().add(pointer);
        }
        for (Map.Entry<String, TransactionOutput> entry : added.entrySet()) {
            blockchain.getMempoolUTXOs().put(entry.getKey(), entry.getValue());
        }
        return true;
    }

    /**
     * Calculates the hash of the transaction. The hash is of the following
     * data: numInputs || each input (serialized) || numOutputs || each output
     * (serialized)
     *
     * @return the double SHA-256 hash of the transaction data.
     */
    public byte[] calculateHash() {
        byte[] numIn = ByteBuffer.allocate(4).putInt(inputs.size()).array();
        byte[] numOut = ByteBuffer.allocate(4).putInt(outputs.size()).array();
        byte[] data = numIn;
        for (TransactionInput input : inputs) {
            data = Bytes.concat(data, input.serialize());
        }
        data = Bytes.concat(data, numOut);
        for (TransactionOutput output : outputs) {
            data = Bytes.concat(data, output.serialize());
        }
        return Hash.doubleSha256(data);
    }

    /**
     * @param index the index of the output to retrieve.
     * @return the TransactionOutput at the given index in the transaction.
     */
    public TransactionOutput getOutput(int index) {
        return outputs.get(index);
    }

    /**
     * @return the inputs of the transaction.
     */
    public ArrayList<TransactionInput> getInputs() {
        return inputs;
    }

    /**
     * @return the outputs of the transaction.
     */
    public ArrayList<TransactionOutput> getOutputs() {
        return outputs;
    }

    /**
     * @return the transaction's hash.
     */
    public byte[] getHash() {
        return hash;
    }

    /**
     * Serializes a transaction into byte form. Format: numInputs (4 bytes) ||
     * serialized inputs (varies) || numOutputs (4 bytes) || serialized outputs
     * (varies)
     *
     * @return a serialized representation of the transaction.
     */
    public byte[] serialize() {
        byte[] numIn = ByteBuffer.allocate(4).putInt(inputs.size()).array();
        byte[] numOut = ByteBuffer.allocate(4).putInt(outputs.size()).array();
        byte[] data = numIn;
        for (TransactionInput input : inputs) {
            data = Bytes.concat(data, input.serialize());
        }
        data = Bytes.concat(data, numOut);
        for (TransactionOutput output : outputs) {
            data = Bytes.concat(data, output.serialize());
        }
        return data;
    }

    /**
     * @return the dump format of the transaction object.
     */
    @Override
    public String toString() {
        String res = "";
        res += "      Hash: " + Bytes.toHex(hash) + "\n";
        for (int i = 0; i < inputs.size(); i++) {
            res += "   Input " + i + ":\n";
            res += inputs.get(i).toString() + "\n";
        }
        for (int i = 0; i < outputs.size(); i++) {
            res += "  Output " + i + ":\n";
            res += outputs.get(i).toString();
        }
        return res;
    }

    /**
     * @param o the Object to compare.
     * @return whether the given object is a Transaction whose hash is
     * equivalent.
     */
    @Override
    public boolean equals(Object o) {
        if (o.getClass() != Transaction.class) {
            return false;
        }
        Transaction other = (Transaction) o;
        return Arrays.equals(other.hash, this.hash);
    }
}
