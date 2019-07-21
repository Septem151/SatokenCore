# SatokenCore
Java Blockchain with no external dependencies based on [Bitcoin](https://github.com/bitcoin/bitcoin). SatokenCore is a demonstration of my knowledge of File Encryption, Blockchain Principles, & Decentralized P2P Systems.
<br>
## What is SatokenCore?
SatokenCore is a decentralized blockchain-based cryptocurrency that is written in Java with no dependencies or libraries except the Core Java libraries.
It primarily uses elements of the Bitcoin blockchain, for ex: hierarchical derivation of addresses, proof-of-work model, similar data structures like chainstate and mempool, etc. Some elements are direct implementations of bitcoin protocols, such as [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) (HD wallets) and [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) (mnemonic generation for deterministic keys).
<br>

The SatokenCore Client broadcasts and receives information to/from other Nodes (known as "Peers") to maintain a ledger of all valid Blocks containing valid Transactions.
Valid is defined as follows:

- Block headers contain the previous Block's hash.
- Difficulties match expected adjustment every 10 Blocks based on a genesis difficulty of 0x00000FFFFFFFFFFF with a max increase of 10% and a max decrease of 15%
- Block headers hash to a lower value than its difficulty
- Blocks contain only valid Transactions
- Transaction Inputs reference existing unspent Outputs
- Input Public Keys hash to the unspent Output PubKeyHashes
- Input Private Keys sign the unspent Output Transaction hashes

A Node is capable of creating Blocks by gathering Transactions from the mempool and hashing the Block header with a different nonce until the Block header hashes to a lower value than its difficulty. The Proof of Work to create a new valid Block should take approximately 10 seconds on average. When a new block is mined or when a new transaction is either created or heard about from another node, the block or transaction is shared to other peers. Nodes maintain a list of valid Transactions they hear about from Peers called the mempool. If a Transaction from the mempool is included in a newly discovered and validated Block, it is removed from the mempool.
<br>

Nodes contain Wallet(s). A Wallet is an interface with many private keys derived in a hierarchical deterministic tree structure. A 12-word mnemonic phrase is used as a seed for deriving new keys. Externally facing keys (Receiving addresses) are derived from the non-hardened 0th child index, whereas internally facing keys (Change addresses) are derived from the non-hardened 1st child index. Whenever a key is used to sign a Transaction, the key will not be used again. When an externally facing key is referenced in a Transaction Output, the key will not be used to receive funds again. When a Node mines a Block, the Coinbase reward is given to whichever Wallet is open at the time of mining. Wallets contain a list of unspent Coins that are relevant to its keys. When a new Block is discovered, each Transaction Output is scanned to check if its PubKeyHash matches a Public Key hash owned by the Wallet. Wallets may also scan the mempool to check for an unconfirmed balance. Wallets are allowed to spend unconfirmed Transactions sitting in the mempool, as it can be assumed the mempool Transactions will eventually be included in a new Block.


## How do I use SatokenCore?
As of <b>SatokenCore v0.1A</b>, networking has not been added as a feature. Thus, the application does not communicate with other nodes yet. The "decentralized" aspect of SatokenCore will come in the next release, <b>v0.1B</b>. However, you may still run the program and use all of its functionality as a singular peer.

### Installation
Find the latest release on the [Releases](https://github.com/Septem151/SatokenCore/releases) page.

### Interaction
SatokenCore uses the command line for user input and interaction. Commands that are valid are generally prefaced with brackets, ex: "[N]" unless stated that a different type of input is required. There are 3 primary menus of SatokenCore:
- Main Menu
  - Create New Wallets, Load Existing Wallets, Recover Wallet from Seed, and Exiting the application.
- Wallet Menu
  - Shows Balance & Receive Address of the current wallet, Send Satoken, Mine Blocks, and Show Options.
- Options Menu
  - Adjust Automine, Generate more keys, & Print information about the blockchain or the current wallet.

Since SatokenCore writes blocks to disk as they are mined and verified, the program can recover from unexpected crashes or terminations. The Chainstate (current set of all unspent transaction outputs) will replay all blocks after the highest known block since the last proper Exiting.

## Contributions
If you wish to contribute to SatokenCore, please submit a Pull Request. I will be actively checking this repository and would love some assistance, especially with the networking & P2P aspect of SatokenCore. Things that are currently needed include:
- [ ] Networking, including Sockets, Socket Threads, Message Threads, & Objects that contain Message data
- [ ] Handling TODO's in the code

## License
SatokenCore is released under the [MIT License](https://opensource.org/licenses/MIT).
