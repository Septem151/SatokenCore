package satokentestnet.struct;

import java.util.Stack;
import java.util.ArrayList;
import java.util.Arrays;
import satokentestnet.crypto.Hash;

/**
 * A Merkle Tree is a binary tree structure whose leaf nodes are hashes of data,
 * and each non-leaf node is the hash of two previous nodes. Merkle trees are
 * used in cryptocurrency to easily compute hashes of blocks in Proof-of-work
 * based systems.
 *
 * @author Carson Mullins
 */
public class MerkleTree {

    private MerkleNode root;
    private final ArrayList<byte[]> leaves;

    /**
     * Default constructor for a Merkle Tree. Attempts to create a new tree
     * structure if the given transactions list is not empty.
     *
     * @param transactions the transactions whose hashes are to be included as
     * leaves.
     */
    public MerkleTree(ArrayList<Transaction> transactions) {
        leaves = new ArrayList<>();
        for (Transaction t : transactions) {
            leaves.add(t.getHash());
        }
        if (!transactions.isEmpty()) {
            buildTree();
        }
    }

    /**
     * Reconstructs the Merkle Tree to calculate the Merkle root. Primarily
     * called on creation of the object as well as whenever a leaf is added or
     * updated.
     */
    private void buildTree() {
        int depth = 1;
        ArrayList<MerkleNode> branches = bottomLevel(leaves);
        while (branches.size() > 1) {
            depth++;
            branches = internalLevel(branches, depth);
        }
        root = branches.get(0);
    }

    /**
     * Adds a transaction's hash to the Merkle Tree leaves and recalculates the
     * Merkle root.
     *
     * @param transaction the transaction whose hash is to be added.
     */
    public void add(Transaction transaction) {
        leaves.add(transaction.getHash());
        buildTree();
    }

    /**
     * Updates the first hash index of the Merkle tree. Used when updating the
     * Coinbase transaction of a block. The Merkle root is then recalculated.
     *
     * @param coinbase the Coinbase transaction whose hash has been changed.
     */
    public void updateFirst(Transaction coinbase) {
        leaves.set(0, coinbase.getHash());
        buildTree();
    }

    /**
     * (CURRENTLY UNUSED) Checks for inclusion of a specific hash at the given
     * index in the Merkle tree. Useful for SPV (simplified payment
     * verification) clients to check inclusion of a specific transaction in a
     * block, in O(log(n)) time.
     *
     * @param merkleRoot the Merkle Root to check inclusion of a given
     * transaction in.
     * @param txID the hash of the transaction that is being checked for
     * inclusion.
     * @param txIndex the index of the given transaction in the Merkle tree.
     * @return whether the transaction is present at the given index in the
     * Merkle tree.
     */
    public static boolean evaluateProof(MerkleNode merkleRoot, byte[] txID, int txIndex) {
        Stack<byte[]> proof = merkleProof(merkleRoot, txIndex);
        byte[] proofRoot = txID;
        while (!proof.isEmpty()) {
            byte[] data = new byte[64];
            byte[] nodeHash = proof.pop();
            byte[] direction = proof.pop();
            if (Arrays.equals(direction, new byte[]{0x00})) {
                System.arraycopy(proofRoot, 0, data, 0, 32);
                System.arraycopy(nodeHash, 0, data, 32, 32);
            } else {
                System.arraycopy(nodeHash, 0, data, 0, 32);
                System.arraycopy(proofRoot, 0, data, 32, 32);
            }
            proofRoot = Hash.sha256(data);
        }
        return Arrays.equals(proofRoot, merkleRoot.hash);
    }

    /**
     * Creates a stack containing byte instructions and hash values for
     * calculating a Merkle root hash from the given index.
     *
     * @param merkleRoot the Merkle Root to calculate from.
     * @param txIndex the index in the Merkle Root that is to be proven.
     * @return the stack of instructions (singular byte 0x01 for left, 0x00 for
     * right, then a hash value following).
     */
    private static Stack<byte[]> merkleProof(MerkleNode merkleRoot, int txIndex) {
        Stack<byte[]> proof = new Stack<>();
        int height = merkleRoot.depth;
        String movements = String.format("%" + height + "s", Integer.toBinaryString(txIndex)).replace(' ', '0');
        int pointer = 0;
        MerkleNode node = merkleRoot;
        while (height > 0) {
            if (movements.charAt(pointer) == '1') {
                proof.push(new byte[]{0x01});
                proof.push(node.left.hash);
                node = node.right;
            } else {
                proof.push(new byte[]{0x00});
                if (node.right != null) {
                    proof.push(node.right.hash);
                } else {
                    proof.push(node.left.hash);
                }
                node = node.left;
            }
            pointer++;
            height--;
        }
        return proof;
    }

    /**
     * @return the Merkle Root of the Merkle Tree.
     */
    public MerkleNode getRoot() {
        return root;
    }

    /**
     * Calculate an internal level within the Merkle tree.
     *
     * @param children the list of children nodes.
     * @param depth the depth at which this level is at.
     * @return the list of nodes at the internal level.
     */
    private ArrayList<MerkleNode> internalLevel(ArrayList<MerkleNode> children, int depth) {
        ArrayList<MerkleNode> branches = new ArrayList<>(children.size() / 2);
        for (int i = 0; i < children.size() - 1; i += 2) {
            MerkleNode child1 = children.get(i);
            MerkleNode child2 = children.get(i + 1);
            MerkleNode branch = constructBranch(child1, child2, depth);
            branches.add(branch);
        }
        if (children.size() % 2 != 0) {
            MerkleNode child = children.get(children.size() - 1);
            MerkleNode branch = constructBranch(child, null, depth);
            branches.add(branch);
        }
        return branches;
    }

    /**
     * Calculates the bottom level (leaves) of a Merkle tree.
     *
     * @param hashes the list of leaf values.
     * @return the list of nodes at the bottom level, depth 1.
     */
    private ArrayList<MerkleNode> bottomLevel(ArrayList<byte[]> hashes) {
        ArrayList<MerkleNode> branches = new ArrayList<>(hashes.size() / 2);
        for (int i = 0; i < hashes.size() - 1; i += 2) {
            MerkleNode leaf1 = constructLeaf(hashes.get(i));
            MerkleNode leaf2 = constructLeaf(hashes.get(i + 1));
            MerkleNode branch = constructBranch(leaf1, leaf2, 1);
            branches.add(branch);
        }
        if (hashes.size() % 2 != 0) {
            MerkleNode leaf = constructLeaf(hashes.get(hashes.size() - 1));
            MerkleNode branch = constructBranch(leaf, null, 1);
            branches.add(branch);
        }
        return branches;
    }

    /**
     * Constructs a branch (a node with two children nodes).
     *
     * @param leaf1 the left child.
     * @param leaf2 the right child.
     * @param depth the depth of the branch in the Merkle tree.
     * @return the Merkle Node whose children are leaf1 and leaf2.
     */
    private MerkleNode constructBranch(MerkleNode leaf1, MerkleNode leaf2, int depth) {
        MerkleNode branch = new MerkleNode();
        branch.depth = depth;
        branch.left = leaf1;
        if (leaf2 == null) {
            branch.right = leaf1;
        } else {
            branch.right = leaf2;
        }
        byte[] hash = new byte[branch.left.hash.length + branch.right.hash.length];
        System.arraycopy(branch.left.hash, 0, hash, 0, hash.length / 2);
        System.arraycopy(branch.right.hash, 0, hash, hash.length / 2, hash.length / 2);
        branch.hash = Hash.sha256(hash);
        return branch;
    }

    /**
     * Constructs a MerkleNode object out of the given hash bytes.
     *
     * @param hash the hash of a transaction in bytes.
     * @return the MerkleNode object whose hash is the given value.
     */
    private MerkleNode constructLeaf(byte[] hash) {
        MerkleNode leaf = new MerkleNode();
        leaf.depth = 0;
        leaf.hash = hash;
        return leaf;
    }
}
