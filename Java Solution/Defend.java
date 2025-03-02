import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/**
 * Defend Your Code - Java Implementation
 * 
 * This program securely collects user input, validates it, processes files,
 * and handles password security using SHA-256 with salting. It ensures robust
 * error handling, prevents crashes, and logs errors properly.
 * 
 * Features:
 * - Validates user names (only letters, hyphen, and apostrophe allowed)
 * - Ensures integer input is within the 4-byte integer range
 * - Implements password security with hashing and salting
 * - Reads an input file and writes required data to an output file
 * - Logs errors in an error file
 * - Ensures program does not crash due to invalid input
 * 
 * @author Lwazi Murad Sophenith 
 */
public class Defend {
    private static final int MAX_NAME_LENGTH = 50;
    private static final String NAME_REGEX = "^[A-Za-z\\-']+$";
    private static final int INT_MIN = Integer.MIN_VALUE;
    private static final int INT_MAX = Integer.MAX_VALUE;
    private static final String PASSWORD_LOG_FILE = "password.txt";
    private static final String ERROR_LOG_FILE = "error.txt";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        PrintWriter errorLog = null;
        
        try {
            errorLog = new PrintWriter(new FileWriter(ERROR_LOG_FILE, true));

            // Read user input: First name, Last name, Integers
            String firstName = readName(scanner, "first");
            String lastName = readName(scanner, "last");

            int firstInt = readInt(scanner, "first");
            int secondInt = readInt(scanner, "second");
            long sum = safeAdd(firstInt, secondInt);
            long product = safeMultiply(firstInt, secondInt);

            // Read input and output file names
            String inputFileName = readFileName(scanner, "input");
            String outputFileName = readFileName(scanner, "output");

            while (inputFileName.equals(outputFileName)) {
                System.out.println("Input and output files must be different.");
                outputFileName = readFileName(scanner, "output");
            }

            // Handle password security
            byte[] salt = generateSalt();
            String hashedPassword = "";

            while (true) {
                System.out.print("Enter a password (min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special character): ");
                String password = scanner.nextLine();
                if (!isValidPassword(password)) {
                    System.out.println("Password does not meet requirements. Try again.");
                    continue;
                }

                System.out.print("Re-enter your password for verification: ");
                String passwordVerify = scanner.nextLine();
                if (!password.equals(passwordVerify)) {
                    System.out.println("Passwords do not match. Try again.");
                    continue;
                }

                hashedPassword = hashPassword(password, salt);
                savePassword(hashedPassword, salt);

                System.out.print("Enter your password once more to verify: ");
                String finalPassword = scanner.nextLine();
                if (hashPassword(finalPassword, salt).equals(hashedPassword)) {
                    System.out.println("Password verified successfully.");
                    break;
                } else {
                    System.out.println("Final Password verification failed. Try again.");
                }
            }

            // Read input file contents
            String inputFileContents = "";
            try {
                inputFileContents = new String(Files.readAllBytes(Paths.get(inputFileName)));
            } catch (IOException e) {
                logError(errorLog, "Error reading input file: " + e.getMessage());
                inputFileContents = "Error reading file";
            }

            // Write to output file
            try (PrintWriter writer = new PrintWriter(new FileWriter(outputFileName))) {
                writer.println("First Name: " + firstName);
                writer.println("Last Name: " + lastName);
                writer.println("First Integer: " + firstInt);
                writer.println("Second Integer: " + secondInt);
                writer.println("Sum: " + sum);
                writer.println("Product: " + product);
                writer.println("Input File Name: " + inputFileName);
                writer.println("Input File Contents:\n" + inputFileContents);
                System.out.println("Data successfully written to " + outputFileName);
            } catch (IOException e) {
                logError(errorLog, "Error writing output file: " + e.getMessage());
            }

        } catch (Exception e) {
            logError(errorLog, "An error occurred: " + e.getMessage());
        } finally {
            if (errorLog != null) errorLog.close();
            scanner.close();
        }
    }

    /**
     * Logs an error message to the error log file.
     */
    private static void logError(PrintWriter errorLog, String message) {
        if (errorLog != null) {
            errorLog.println(new Date() + ": " + message);
            errorLog.flush();
        }
    }

    /**
     * Reads and validates a name (first or last).
     */
    private static String readName(Scanner scanner, String type) {
        while (true) {
            System.out.print("Enter your " + type + " name (letters, hyphen (-), apostrophe (') allowed, max " + MAX_NAME_LENGTH + " characters): ");
            String name = scanner.nextLine();
            if (name.length() > 0 && name.length() <= MAX_NAME_LENGTH && name.matches(NAME_REGEX)) {
                return name;
            }
            System.out.println("Invalid name. Please enter again.");
        }
    }

    /**
     * Reads and validates an integer.
     */
    private static int readInt(Scanner scanner, String order) {
        while (true) {
            System.out.print("Enter the " + order + " integer (range: " + INT_MIN + " to " + INT_MAX + "): ");
            try {
                return Integer.parseInt(scanner.nextLine());
            } catch (NumberFormatException e) {
                System.out.println("Invalid integer input. Please enter a valid 4-byte integer.");
            }
        }
    }

    /**
     * Reads a valid file name and ensures input files exist.
     */
    private static String readFileName(Scanner scanner, String type) {
        while (true) {
            System.out.print("Enter the " + type + " file name (e.g., file.txt): ");
            String fileName = scanner.nextLine();
            if (!fileName.isEmpty()) {
                if (type.equalsIgnoreCase("input")) {
                    if (new File(fileName).exists()) return fileName;
                    System.out.println("File does not exist. Try again.");
                } else {
                    return fileName;
                }
            } else {
                System.out.println("File name cannot be empty.");
            }
        }
    }

    /**
     * Validates a password according to complexity requirements.
     */
    private static boolean isValidPassword(String password) {
        if (password.length() < 8) return false;
        return password.matches("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*()_+=<>?/{}~|]).+$");
    }

    /**
     * Generates a secure random salt.
     */
    private static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Hashes a password using SHA-256 and a provided salt.
     */
    private static String hashPassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hashed = md.digest(password.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashed) hexString.append(String.format("%02x", b));
            return hexString.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Saves the hashed password and salt to a file.
     */
    private static void savePassword(String hashedPassword, byte[] salt) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(PASSWORD_LOG_FILE))) {
            pw.println(Base64.getEncoder().encodeToString(salt));
            pw.println(hashedPassword);
        } catch (IOException e) {
            System.out.println("Error saving password.");
        }
    }

    private static long safeAdd(int a, int b) {
        return (long) a + (long) b;
    }

    private static long safeMultiply(int a, int b) {
        return (long) a * (long) b;
    }
}