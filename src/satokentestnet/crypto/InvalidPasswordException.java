package satokentestnet.crypto;

/**
 * Exception class representing an invalid password attempt.
 *
 * @author Carson Mullins
 */
public class InvalidPasswordException extends Exception {

    /**
     * Constructor for an InvalidPasswordException.
     */
    public InvalidPasswordException() {

    }

    /**
     * @return a String representation of the exception.
     */
    @Override
    public String toString() {
        return "Invalid Password.";
    }
}
