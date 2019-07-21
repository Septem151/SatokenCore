package satokentestnet.struct;

/**
 * A Merkle Node that is used in a Merkle Tree. Each Node has 2 children nodes,
 * the content of the node (a hash), and the depth of the node in the Tree.
 *
 * @author Carson Mullins
 */
public class MerkleNode {

    public byte[] hash;
    public MerkleNode left, right;
    public int depth;
}
