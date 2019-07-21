# SatokenCore
Java Blockchain with no external dependencies based on [Bitcoin](https://github.com/bitcoin/bitcoin). SatokenCore is a demonstration of my knowledge of File Encryption, Blockchain Principles, & Decentralized P2P Systems.
<br>
## What is SatokenCore?
SatokenCore is a decentralized blockchain-based cryptocurrency that is written in Java with no dependencies or libraries except the Core Java libraries.
It primarily uses elements of the Bitcoin blockchain, for ex: hierarchical derivation of addresses, proof-of-work model, similar data structures like chainstate and mempool, etc. Some elements are direct implementations of bitcoin protocols, such as [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) (HD wallets) and [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) (mnemonic generation for deterministic keys).
<br>
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
