package satokentestnet.client;

import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.BufferedOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Arrays;
import satokentestnet.crypto.DataCipher;
import satokentestnet.crypto.InvalidPasswordException;
import satokentestnet.struct.Block;
import satokentestnet.struct.Blockchain;
import satokentestnet.struct.Transaction;
import satokentestnet.struct.TransactionOutput;
import satokentestnet.util.Strings;

/**
 * SatokenCore is a decentralized blockchain-based cryptocurrency that is
 * written in Java with no dependencies or libraries except the Core Java
 * libraries. It primarily uses elements of the Bitcoin blockchain, for ex:
 * hierarchical derivation of addresses, proof-of-work model, similar data
 * structures like chainstate and mempool, etc. Some elements are direct
 * implementations of bitcoin protocols, such as BIP32 (HD wallets) and BIP39
 * (mnemonic generation for deterministic keys).
 * @author Carso
 */
public class Driver {

    public static final String rootDir = (System.getProperty("os.name").startsWith("Windows")
            ? System.getenv("SystemDrive") + "/" : "/");
    public static final String dataDir = rootDir + "SatokenCore/testnet/";
    public static final String walletDir = dataDir + "wallets/";
    public static final String wordListPath = dataDir + "WordList.txt";
    public static final String blocksPath = dataDir + "blocks.dat";
    public static final String statePath = dataDir + "state.dat";
    public static final String wordListURL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt";
    public static boolean automine = false;
    public static int numAutomine = 5;
    private static Wallet currentWallet = null;
    private static File currentWalletFile = null;
    private static final Blockchain blockchain = Blockchain.getInstance();
    public static final PrintStream cli = System.out;
    private static final Scanner userIn = new Scanner(System.in);
    private static final Console console = System.console();

    /**
     * Entry point of the SatokenCore application. All user input comes through
     * the Driver. Loads the relevant data directories, loads blocks and
     * Chainstate into application memory if applicable, and prompts user to
     * create a new wallet, load an existing wallet, or recover a wallet using a
     * seed phrase.
     *
     * @param args the command line arguments (none required, has no effect)
     */
    public static void main(String[] args) {

        cli.print("Checking for Data directory.");
        File folder = new File(dataDir);
        if (!folder.exists()) {
            cli.print(" Creating Data directory.");
            folder.mkdirs();
        }
        cli.print(" OK\nChecking for Wallet directory.");
        folder = new File(walletDir);
        if (!folder.exists()) {
            cli.print(" Creating Wallet directory.");
            folder.mkdir();
        }
        cli.print(" OK\nChecking for Blocks file.");
        File file = new File(blocksPath);
        try {
            if (!file.exists()) {
                cli.print(" Creating Blocks file.");
                file.createNewFile();
            } else {
                cli.print(" Loading Blocks file.");
            }
            byte[] data = Files.readAllBytes(file.toPath());
            Blockchain.getInstance().deserializeBlocks(data);
        } catch (IOException ex) {
            System.out.println("Error reading/writing to blocks.dat file.");
            System.exit(1);
        }
        cli.print(" OK\nChecking for State file.");
        file = new File(statePath);
        try {
            if (!file.exists()) {
                cli.print(" Creating State file.");
                file.createNewFile();
            } else {
                cli.print(" Loading State file.");
            }
            byte[] data = Files.readAllBytes(file.toPath());
            Blockchain.getInstance().deserializeState(data);
        } catch (IOException ex) {
            System.out.println("Error creating state.dat file.");
            System.exit(1);
        }
        cli.print(" OK\nChecking for Word List file.");
        try {
            file = new File(wordListPath);
            if (!file.exists()) {
                cli.print(" Downloading Word List.");
                file.createNewFile();
                URL url = new URL(wordListURL);
                ReadableByteChannel readableByteChannel = Channels.newChannel(url.openStream());
                try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
                    FileChannel fileChannel = fileOutputStream.getChannel();
                    fileChannel.transferFrom(readableByteChannel, 0, Long.MAX_VALUE);
                }
            }
        } catch (IOException ex) {
            System.out.println("Exception occurred.");
            throw new RuntimeException(ex);
        }
        cli.println(" OK");
        if (blockchain.getHeight() == 0) {
            cli.print("Creating Genesis Block.");
            blockchain.mineGenesisBlock();
            cli.println(" OK\n");
        }
        pause(3000);
        // Main Program Loop
        boolean running = true;
        while (running) {
            clearScreen();
            cli.println("\t\tMain Menu");
            cli.println("Create, load, or recover a wallet.");
            cli.println("[N] - New Wallet");
            cli.println("[L] - Load Wallet");
            cli.println("[R] - Recover Wallet");
            cli.println("[Q] - Quit Satoken Core Client");
            String input = userIn.nextLine();
            cli.println();
            switch (input.toUpperCase()) {
                case "N":
                    createWallet();
                    break;
                case "L":
                    loadWallet();
                    break;
                case "R":
                    recoverWallet();
                    break;
                case "Q":
                    running = false;
                    saveAndQuit();
                    break;
                default:
                    inputError(input);
            }
        }
        userIn.close();
    }

    /**
     * The Wallet Menu is opened when a wallet is loaded. This is how the user
     * interacts with the wallet, ex: Checking balance, creating new
     * transactions, checking for receive addresses, mining new blocks, and
     * printing out Blockchain information.
     *
     * @param password the wallet file's password. Necessary to pass as a
     * parameter to be able to encrypt the file after changing its data.
     */
    private static void walletMenu(char[] password) {
        // TODO: Is it secure to pass the password as a parameter and keep it 
        // sitting in program memory for so long? There has to be a better way to handle this.
        boolean running = true;
        while (running) {
            clearScreen();
            currentWallet.updateBalance();
            cli.println("\t\tWallet Menu");
            cli.println("          Balance: " + currentWallet.printBalance());
            cli.println("Receiving Address: " + currentWallet.getReceiveAddress());
            cli.println("[S] - Send Satoken");
            cli.println("[M] - Mine Block");
            cli.println("[O] - Options");
            cli.println("[Q] - Exit Wallet");
            String input = userIn.nextLine();
            cli.println();
            switch (input.toUpperCase()) {
                case "S":
                    transactionMenu();
                    break;
                case "M":
                    int quantity = (automine) ? numAutomine : 1;
                    while (quantity > 0) {
                        currentWallet.updateBalance();
                        cli.print("Mining " + quantity + " new Block" + (quantity > 1 ? "s" : "") + ".");
                        Block block = new Block(blockchain.getLastBlock());
                        block.mine(currentWallet.getReceivePubKey());
                        cli.print(" Block Found.");
                        if (blockchain.writeBlockToDisk(block)) {
                            cli.println(" Block Verified.\n");
                            pause(1000);
                        } else {
                            cli.println(" Block Rejected.\n");
                            pause(1000);
                            break;
                        }
                        if (quantity > 1) {
                            clearScreen();
                            currentWallet.updateBalance();
                            cli.println("\t\tWallet Menu");
                            cli.println("          Balance: " + currentWallet.printBalance());
                            cli.println("Receiving Address: " + currentWallet.getReceiveAddress());
                            cli.println("[S] - Send Satoken");
                            cli.println("[M] - Mine Block");
                            cli.println("[O] - Options");
                            cli.println("[Q] - Exit Wallet\n");
                        }
                        quantity--;
                    }
                    break;
                case "O":
                    optionsMenu();
                    break;
                case "Q":
                    running = false;
                    break;
                default:
                    inputError(input);
            }
        }
        try {
            byte[] walletData = DataCipher.encryptData(currentWallet.serialize(), password);
            try (BufferedOutputStream fOut = new BufferedOutputStream(new FileOutputStream(currentWalletFile, false))) {
                fOut.write(walletData);
            }
        } catch (IOException ex) {
            cli.println("Critical Error: Failed to save Wallet data upon closing.");
            System.exit(1);
        }
        currentWallet = null;
    }

    /**
     * The Transaction Menu is opened when creating a new Transaction from the
     * Wallet Menu. Asks for number of recipients, recipient addresses, and
     * values to receive.
     */
    private static void transactionMenu() {
        clearScreen();
        String input = "";
        int numRecipients = 0;
        ArrayList<TransactionOutput> outputs = new ArrayList<>();
        cli.println("\t\tCreate New Transaction");
        boolean proceed = false;
        while (!proceed) {
            cli.println("Balance: " + currentWallet.printBalance());
            cli.print("# of Recipients (Q to cancel): ");
            try {
                input = userIn.nextLine();
                cli.println();
                if (input.equalsIgnoreCase("Q")) {
                    return;
                }
                numRecipients = Integer.parseInt(input);
                if (numRecipients <= 0) {
                    cli.println("Number of recipients must be larger than 0.\n");
                } else {
                    proceed = true;
                }
            } catch (NumberFormatException ex) {
                inputError(input);
            }
        }
        for (int i = 0; i < numRecipients; i++) {
            proceed = false;
            boolean validRecipient = false;
            while (!proceed) {
                try {
                    byte[] pubKeyHash = new byte[0];
                    if (!validRecipient) {
                        cli.print("Recipient " + (i + 1) + " (Q to cancel): ");
                        input = userIn.nextLine();
                        if (input.equalsIgnoreCase("Q")) {
                            cli.println();
                            return;
                        }
                        pubKeyHash = Strings.decodeAddress(input);
                        validRecipient = true;
                    }
                    cli.print("     Amount (Q to cancel): ");
                    input = userIn.nextLine();
                    cli.println();
                    if (input.equalsIgnoreCase("Q")) {
                        return;
                    }
                    String[] digits = input.split("\\.");
                    if (digits.length > 2 || input.endsWith(".")) {
                        throw new NumberFormatException();
                    } else if (digits.length == 2) {
                        if (digits[1].length() > 8) {
                            cli.println("Too precise of a value. Max 8 decimal places.\n");
                            continue;
                        }
                        digits[1] = String.format("%-8s", digits[1]).replace(' ', '0');
                        input = digits[0] + digits[1];
                    } else {
                        input += "00000000";
                    }
                    long value = Long.parseLong(input);
                    outputs.add(new TransactionOutput(value, pubKeyHash));
                    proceed = true;
                } catch (Exception ex) {
                    if (ex instanceof NumberFormatException) {
                        cli.println(input + " is not a valid value.\n");
                    } else {
                        cli.println("\nNot a valid address.\n");
                    }
                }
            }
        }
        proceed = false;
        while (!proceed) {
            cli.println("Sign and Broadcast Transaction? (Y/N)");
            input = userIn.nextLine();
            cli.println();
            switch (input.toUpperCase()) {
                case "Y":
                    proceed = true;
                    break;
                case "N":
                    cli.println("Transaction cancelled and discarded.\n");
                    pause(2000);
                    return;
                default:
                    inputError(input);
            }
        }
        Transaction transaction = currentWallet.buildTransaction(outputs);
        if (transaction != null) {
            // Verify Transaction
            if (!transaction.verify()) {
                cli.println("Transaction did not verify.\n");
            } else {
                cli.println("Transaction added to mempool.\n");
            }
        }
        pause(2000);
    }

    /**
     * The Options Menu is opened when changing options from the Wallet Menu.
     * Options include setting up automine, generating new wallet keys, and
     * printing various information about the wallet and the Blockchain.
     */
    private static void optionsMenu() {
        boolean proceed = false;
        while (!proceed) {
            clearScreen();
            cli.println("\t\tOptions Menu");
            cli.println("Print information or adjust Mining settings.");
            cli.println("[A] - Automine (" + (automine ? "ON, " + numAutomine + " Blocks" : "OFF") + ")");
            cli.println("[G] - Generate More Keys");
            cli.println("[B] - Print Recent Blocks");
            cli.println("[C] - Print Chainstate");
            cli.println("[M] - Print Mempool");
            cli.println("[W] - Print Wallet");
            cli.println("[Q] - Back to Wallet Menu");
            String input = userIn.nextLine();
            cli.println();
            switch (input.toUpperCase()) {
                case "A":
                    if (!automine) {
                        adjustAutomine();
                    } else {
                        automine = false;
                        cli.println("Automine has been turned off.\n");
                        pause(1000);
                    }
                    break;
                case "G":
                    genMoreKeys();
                    break;
                case "B":
                    cli.println("\t\tBlockchain (Current Height: " + blockchain.getHeight() + ")\n");
                    cli.println(blockchain.toString());
                    cli.print("Enter to continue");
                    userIn.nextLine();
                    break;
                case "C":
                    cli.println("\t\tChainstate (Size: " + blockchain.getChainstate().size() + ")\n");
                    cli.println(blockchain.chainstateString());
                    cli.print("Enter to continue");
                    userIn.nextLine();
                    break;
                case "M":
                    cli.println("\t\tMempool (Size: " + blockchain.getMempool().size() + ")\n");
                    cli.println(blockchain.mempoolString());
                    cli.print("Enter to continue");
                    userIn.nextLine();
                    break;
                case "W":
                    cli.println("\t\tWallet Data\n");
                    cli.println(currentWallet.toString());
                    cli.print("Enter to continue");
                    userIn.nextLine();
                    break;
                case "Q":
                    return;
                default:
                    inputError(input);
            }
        }
    }

    /**
     * Dialog for generating more keys in the given wallet.
     */
    private static void genMoreKeys() {
        clearScreen();
        while (true) {
            cli.println("\t\tNew Keys Generation");
            cli.println("WARNING: Too many keys will cause wallet load time to increase.");
            cli.println("         It is recommended to switch wallets after ~200 keys.");
            cli.print("# of Keys to generate (Q to cancel): ");
            try {
                String input = userIn.nextLine();
                if (input.equalsIgnoreCase("Q")) {
                    return;
                }
                cli.println();
                int numKeys = Integer.parseInt(input);
                if (numKeys <= 0) {
                    throw new NumberFormatException();
                }
                cli.print("Generating " + numKeys + " Keys.");
                for (int i = 0; i < numKeys; i++) {
                    currentWallet.genExternalKey();
                    currentWallet.genInternalKey();
                }
                cli.println(" OK\n");
                return;
            } catch (NumberFormatException ex) {
                cli.println("Only positive, non-zero numbers are allowed.\n");
            }
        }
    }

    /**
     * Dialog for setting how many blocks automine will mine.
     */
    private static void adjustAutomine() {
        clearScreen();
        while (true) {
            cli.println("\t\tAdjust Automine Blocks");
            cli.print("# of Blocks to mine (Q to cancel): ");
            try {
                String input = userIn.nextLine();
                if (input.equalsIgnoreCase("Q")) {
                    return;
                }
                cli.println();
                numAutomine = Integer.parseInt(input);
                if (numAutomine <= 0) {
                    throw new NumberFormatException();
                }
                cli.println("Automine has been enabled.\n");
                automine = true;
                pause(1000);
                return;
            } catch (NumberFormatException ex) {
                cli.println("Only positive, non-zero numbers are allowed.\n");
                pause(1000);
            }
        }
    }

    /**
     * Logic for creating a new wallet and storing the wallet's data in a file
     * on disk. User is prompted for the File Name, the wallet's passphrase
     * (optional) used for deriving keys, the wallet's derivation path
     * (optional) which will default to
     * {@value satokentestnet.client.Wallet#defaultDerivation} if none is
     * supplied, and the password for encrypting the File itself. The Wallet
     * created is then set as the Node's Wallet for spending and block rewards.
     * The wallet is stored on disk at {@value #walletDir}.
     */
    private static void createWallet() {
        String fileName = "";
        char[] passphrase = new char[0];
        String derivationPath = Wallet.defaultDerivation;
        char[] password = new char[0];
        boolean proceed;
        clearScreen();
        cli.println("\t\tCreate A New Wallet");
        fileName = "";
        boolean validFileName = false;
        while (!validFileName) {
            cli.print("File Name: ");
            fileName = userIn.nextLine();
            if (fileName.isEmpty()) {
                cli.println("File name cannot be empty.\n");
                continue;
            }
            File[] walletFiles = getWalletFiles();
            if (walletFiles.length == 0) {
                validFileName = true;
            } else {
                for (File file : walletFiles) {
                    if (file.getName().equalsIgnoreCase(fileName + ".dat")) {
                        cli.println("File name already exists.\n");
                        validFileName = false;
                        break;
                    } else {
                        validFileName = true;
                    }
                }
            }
        }
        proceed = false;
        boolean advanced = false;
        while (!proceed) {
            cli.println("Advanced Options? (Y/N)");
            String input = userIn.nextLine();
            switch (input.toUpperCase()) {
                case "Y":
                    proceed = true;
                    advanced = true;
                    break;
                case "N":
                    proceed = true;
                    break;
                default:
                    inputError(input);
            }
        }
        if (advanced) {
            proceed = false;
            while (!proceed) {
                cli.print("Passphrase: ");
                passphrase = console.readPassword();
                if (passphrase.length == 0) {
                    break;
                }
                cli.print("Re-enter Passphrase: ");
                char[] temp = console.readPassword();
                if (!Arrays.equals(passphrase, temp)) {
                    cli.println("Passphrase entered does not match.\n");
                } else {
                    proceed = true;
                }
            }
            proceed = false;
            while (!proceed) {
                cli.print("Derivation Path (ex: m/0'/0'): ");
                derivationPath = userIn.nextLine();
                if (derivationPath.isEmpty()) {
                    derivationPath = Wallet.defaultDerivation;
                }
                proceed = Wallet.validateDerivation(derivationPath);
                if (!proceed) {
                    cli.println("Derivation Path is not valid.\n");
                }
            }
        }
        proceed = false;
        while (!proceed) {
            cli.print("File Password: ");
            password = console.readPassword();
            if (password.length == 0) {
                break;
            } else if (!satisfyPasswordReqs(password)) {
                cli.println("Password does not meet the requirements.");
                cli.println("- At least 8 characters");
                cli.println("- At least 1 uppercase letter");
                cli.println("- At least 1 lowercase letter");
                cli.println("- At least 1 number\n");
                pause(1000);
                continue;
            }
            cli.print("Re-enter Password: ");
            char[] temp = console.readPassword();
            if (!Arrays.equals(password, temp)) {
                cli.println("Password entered does not match.\n");
            } else {
                proceed = true;
            }
        }
        proceed = false;
        while (!proceed) {
            cli.println("Create Wallet? (Y/N)");
            String input = userIn.nextLine();
            cli.println();
            switch (input.toUpperCase()) {
                case "Y":
                    proceed = true;
                    break;
                case "N":
                    cli.println("Wallet not created.\n");
                    return;
                default:
                    inputError(input);
            }
        }
        cli.print("Creating wallet.");
        File walletFile = new File(walletDir + fileName + ".dat");
        try {
            if (!walletFile.createNewFile()) {
                throw new IOException();
            }
            currentWallet = new Wallet(passphrase, derivationPath);
            currentWalletFile = walletFile;
            byte[] walletData = currentWallet.serialize();
            byte[] fileData = DataCipher.encryptData(walletData, password);
            try (FileOutputStream fos = new FileOutputStream(walletFile.getAbsolutePath())) {
                fos.write(fileData);
            }
        } catch (IOException ex) {
            cli.println("Error while creating Wallet File.");
            cli.println("Wallet not created.\n");
            return;
        }
        cli.println(" OK\n");
        cli.println("Take note of your Recovery Seed:");
        cli.println("WARNING! THIS WILL NOT BE SHOWN AGAIN.\n");
        cli.println(new String(currentWallet.getMnemonic()) + "\n");
        pause(3000);
        cli.print("Enter to continue");
        userIn.nextLine();
        walletMenu(password);
    }

    /**
     * The Load Wallet Menu allows the user to load a wallet from a file on
     * disk, given that the wallet is within the wallet data directory. If the
     * wallet directory contains no files, the user is taken back to the main
     * menu.
     */
    private static void loadWallet() {
        char[] password = new char[0];
        currentWallet = null;
        int index = 0;
        boolean valid = false;
        File[] wallets = getWalletFiles();
        while (!valid) {
            clearScreen();
            cli.println("\t\tLoad Existing Wallet");
            if (wallets.length == 0) {
                cli.println("Wallets directory is empty!\n");
                pause(1000);
                return;
            }
            for (int i = 1; i <= wallets.length; i++) {
                cli.println("[" + i + "] - " + wallets[i - 1].getName());
            }
            cli.println("[Q] - Back to Main Menu");
            String selection = userIn.nextLine();
            cli.println();
            try {
                index = Integer.parseInt(selection);
                if (index > 0 && index <= wallets.length) {
                    File file = wallets[index - 1];
                    byte[] fileData = Files.readAllBytes(file.toPath());
                    if (fileData[0] == DataCipher.encryptionFlag) {
                        cli.print("Password: ");
                        password = console.readPassword();
                    }
                    byte[] walletData = DataCipher.decryptData(fileData, password);
                    cli.print("Loading Wallet.");
                    currentWallet = Wallet.deserialize(walletData);
                    currentWalletFile = wallets[index - 1];
                    valid = true;
                } else {
                    inputError(selection);
                }
            } catch (NumberFormatException ex) {
                if (selection.equalsIgnoreCase("Q")) {
                    return;
                } else {
                    inputError(selection);
                }
            } catch (IOException ex) {
                cli.println("Error loading wallet file.");
                System.exit(1);
            } catch (InvalidPasswordException ex) {
                cli.println("Invalid password.\n");
            }
        }
        cli.println(" OK");
        cli.println();
        walletMenu(password);
    }

    /**
     * The Recover Wallet Menu allows the user to recover a wallet from a seed
     * phrase. They may also enter a passphrase (optional), the derivation path
     * (optional), and are prompted to enter a File Name to save the wallet to
     * as well as the password to encrypt the File with.
     */
    private static void recoverWallet() {
        char[] mnemonic;
        char[] passphrase = new char[0];
        String derivationPath = Wallet.defaultDerivation;
        String fileName = "";
        char[] password = new char[0];
        clearScreen();
        cli.println("\t\tRecover A Wallet");
        cli.print("Seed Phrase (Q to cancel): ");
        String input = userIn.nextLine();
        if (input.equalsIgnoreCase("Q")) {
            return;
        }
        mnemonic = input.toCharArray();
        boolean proceed = false;
        boolean advanced = false;
        while (!proceed) {
            cli.println("Advanced Options? (Y/N)");
            input = userIn.nextLine();
            switch (input.toUpperCase()) {
                case "Y":
                    advanced = true;
                    proceed = true;
                    break;
                case "N":
                    proceed = true;
                    break;
                default:
                    inputError(input);
            }
        }
        if (advanced) {
            proceed = false;
            while (!proceed) {
                cli.print("Passphrase: ");
                passphrase = console.readPassword();
                if (passphrase.length == 0) {
                    break;
                }
                cli.print("Re-enter Passphrase: ");
                char[] temp = console.readPassword();
                if (!Arrays.equals(passphrase, temp)) {
                    cli.println("Passphrase entered does not match.\n");
                } else {
                    proceed = true;
                }
            }
            proceed = false;
            while (!proceed) {
                cli.print("Derivation Path (ex: m/0'/0'): ");
                derivationPath = userIn.nextLine();
                if (derivationPath.isEmpty()) {
                    derivationPath = Wallet.defaultDerivation;
                }
                proceed = Wallet.validateDerivation(derivationPath);
                if (!proceed) {
                    cli.println("Derivation Path is not valid.\n");
                }
            }
        }
        boolean validFileName = false;
        while (!validFileName) {
            cli.print("File Name: ");
            fileName = userIn.nextLine();
            if (fileName.isEmpty()) {
                cli.println("File name cannot be empty.\n");
                continue;
            }
            File[] walletFiles = getWalletFiles();
            if (walletFiles.length == 0) {
                validFileName = true;
            } else {
                for (File file : walletFiles) {
                    if (file.getName().equalsIgnoreCase(fileName + ".dat")) {
                        cli.println("File name already exists.\n");
                        validFileName = false;
                        break;
                    } else {
                        validFileName = true;
                    }
                }
            }
        }
        proceed = false;
        while (!proceed) {
            cli.print("File Password: ");
            password = console.readPassword();
            if (password.length == 0) {
                break;
            } else if (!satisfyPasswordReqs(password)) {
                cli.println("Password does not meet the requirements.");
                cli.println("- At least 8 characters");
                cli.println("- At least 1 uppercase letter");
                cli.println("- At least 1 lowercase letter");
                cli.println("- At least 1 number\n");
                pause(1000);
                continue;
            }
            cli.print("Re-enter Password: ");
            char[] temp = console.readPassword();
            if (!Arrays.equals(password, temp)) {
                cli.println("Password entered does not match.\n");
            } else {
                proceed = true;
            }
        }
        proceed = false;
        while (!proceed) {
            cli.println("Create Wallet? (Y/N)");
            input = userIn.nextLine();
            cli.println();
            switch (input.toUpperCase()) {
                case "Y":
                    proceed = true;
                    break;
                case "N":
                    cli.println("Wallet not created.\n");
                    return;
                default:
                    inputError(input);
            }
        }
        File walletFile = new File(walletDir + fileName + ".dat");
        try {
            if (!walletFile.createNewFile()) {
                throw new IOException();
            }
            currentWallet = new Wallet(mnemonic, passphrase, derivationPath);
            currentWalletFile = walletFile;
            byte[] walletData = currentWallet.serialize();
            byte[] fileData = DataCipher.encryptData(walletData, password);
            try (FileOutputStream fos = new FileOutputStream(walletFile.getAbsolutePath())) {
                fos.write(fileData);
            }
        } catch (IOException ex) {
            cli.println("Error while creating Wallet File.");
            cli.println("Wallet not created.\n");
            pause(2000);
            return;
        }
        walletMenu(password);
    }

    /**
     * Saves the Chainstate to file. Blocks are saved as they are mined, but to
     * prevent needing to write tons of data in the event the Chainstate gets
     * too large, it is only updated on program close. This is because the
     * Chainstate is not an ordered structure like the blocks data and may also
     * remove entries between blocks.
     */
    private static void saveAndQuit() {
        cli.print("Saving chainstate.");
        byte[] stateData = Blockchain.getInstance().serializeState();
        try {
            File file = new File(statePath);
            try (BufferedOutputStream fos = new BufferedOutputStream(new FileOutputStream(file))) {
                fos.write(stateData);
            }
            cli.println(" OK");
        } catch (IOException ex) {
            System.out.println("Error saving data to file.");
            System.exit(1);
        }
    }

    /**
     * Prints an error message for invalid commands.
     *
     * @param input the {@code String} command that was attempted.
     */
    public static void inputError(String input) {
        cli.println(input + " is not recognized as a valid command.");
        pause(1000);
    }

    /**
     * Retrieve an array of wallet files stored in {@value #walletDir}.
     *
     * @return a {@code File[]} object containing all files found.
     */
    private static File[] getWalletFiles() {
        File folder = new File(walletDir);
        if (!folder.exists()) {
            folder.mkdirs();
        }
        return folder.listFiles();
    }

    /**
     * Verifies that a password matches the given requirements: - minimum of 8
     * characters in length - at least 1 uppercase letter - at least 1 lowercase
     * letter - at least 1 number
     *
     * @param password the password to verify.
     * @return whether the password satisfies the requirements.
     */
    public static boolean satisfyPasswordReqs(char[] password) {
        return password.length >= 8 && new String(password).matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$");
    }

    /**
     * Pauses the main Thread for a given amount of time.
     *
     * @param milliseconds the time to pause the Thread for.
     */
    public static void pause(int milliseconds) {
        try {
            Thread.sleep(milliseconds);
        } catch (InterruptedException e) {
            cli.println("Exception while sleeping thread.");
        }
    }

    /**
     * Clears the console screen. Works on Linux and Windows, but has not been
     * tested with macOS.
     */
    public static void clearScreen() {
        String system = System.getProperty("os.name");
        if (system.startsWith("Linux")) {
            System.out.print("\033[H\033[2J");
            System.out.flush();
        } else if (system.startsWith("Windows")) {
            try {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } catch (IOException | InterruptedException ex) {
                cli.println("Exception while clearing screen.");
            }
        }
        cli.println("################################################################################");
        cli.println("                         SATOKEN CORE CLIENT v0.1 Alpha");
        cli.println("################################################################################\n");
    }

}
