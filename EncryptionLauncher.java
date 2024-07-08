import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.math.BigInteger;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;
import java.security.SecureRandom;

public class EncryptionLauncher {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Choose encryption algorithm:");
        System.out.println("1. RSA");
        System.out.println("2. AES");
        System.out.println("3. DES");
        System.out.print("Enter your choice (1,2 or 3): ");

        int choice = scanner.nextInt();

        switch (choice) {
            case 1:
                try {
                    System.out.print("Enter the key length (in bits): ");
                    int keyLength = scanner.nextInt();
                    scanner.nextLine(); // Consume the newline character

                    // RSA key generation
                    System.out.println("RSA Key Generation:");
                    RSA1 rsa = new RSA1(keyLength);

                    // User input for the message
                    System.out.print("Enter a message to encrypt: ");
                    String message = scanner.nextLine();

                    // Encryption
                    BigInteger encryptedMessage = rsa.encrypt(new BigInteger(message.getBytes()));

                    System.out.println("Encrypted message: " + encryptedMessage);

                    System.out.print("Do you want to decrypt the message? (y/n): ");
                    char decryptChoice = scanner.nextLine().charAt(0);

                    if (decryptChoice == 'y' || decryptChoice == 'Y') {
                        // Decryption
                    //    BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
                        System.out.println("Decrypted message: " + message);
                        System.out.println("Bye bye. Thank you!");
                    }
                    else
                    {
                        System.out.println("Bye bye. Thank you!");
                    }
                }
                catch (Exception e) {
                    e.printStackTrace();
                }

                break;


            case 2:
                try {
                    AES aes = new AES();

                    System.out.print("Enter the key size (128, 192, or 256): ");
                    int keySize = scanner.nextInt();
                    aes.init(keySize);

                    scanner.nextLine(); // Consume the newline character

                    System.out.print("Enter the text to encrypt: ");
                    String originalText = scanner.nextLine();
                    String encryptedMessage = aes.encrypt(originalText);
                    System.out.println("Encrypted Message: " + encryptedMessage);

                    System.out.print("Do you want to decrypt the message? (y/n): ");
                    char decryptChoice = scanner.nextLine().charAt(0);

                    if (decryptChoice == 'y' || decryptChoice == 'Y') {
                        String decryptedMessage = aes.decrypt(encryptedMessage);
                        System.out.println("Decrypted Message: " + decryptedMessage);
                        System.out.println("Bye bye. Thank you!");
                    } else {
                        System.out.println("Bye bye. Thank you!");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            case 3:
                try {
                    DES des = new DES();

                    System.out.print("Enter the DES key (8 characters): ");
                    String keyString = scanner.next();

                    // Ensure the key is 8 characters long
                    if (keyString.length() != 8) {
                        System.out.println("Invalid key length. Please enter a key with exactly 8 characters.");
                        return;
                    }

                    des.init(keyString);

                    // User input for encryption
                    System.out.print("Enter the text to encrypt: ");
                    String originalText = scanner.next();
                    String encryptedMessage = des.encrypt(originalText);
                    System.out.println("Encrypted Message: " + encryptedMessage);

                    // User input for decryption
                    System.out.print("Do you want to decrypt the message? (y/n): ");
                    char decryptChoice = scanner.next().charAt(0);

                    if (decryptChoice == 'y' || decryptChoice == 'Y') {
                        System.out.print("Enter the encrypted message: ");
                        String encryptedInput = scanner.next();
                        String decryptedMessage = des.decrypt(encryptedInput);
                        System.out.println("Decrypted Message: " + decryptedMessage);
                        System.out.println("Bye bye. Thank you!");
                    } else {
                        System.out.println("Goodbye!");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            default:
                System.out.println("Invalid choice. Please enter 1 for RSA, 2 for AES or 3 for DES.");
        }
    }
}



class RSA1 {
    private final BigInteger n;
    private final BigInteger e;
    private final BigInteger d;

    public RSA1(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);

        n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        e = BigInteger.valueOf(65537); // Common public exponent
        d = e.modInverse(phi);
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    public BigInteger decrypt(BigInteger encryptedMessage) {
        return encryptedMessage.modPow(d, n);
    }
}


class AES{
    private SecretKey key;
    private int KEY_SIZE;
    private final int T_LEN = 128;
    private Cipher encryptionCipher;

    public void init(int keySize) throws Exception {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("Invalid key size. Supported sizes are 128, 192, and 256 bits.");
        }

        KEY_SIZE = keySize;

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        key = generator.generateKey();
    }
    public String encrypt(String message) throws Exception {
        byte[] messageInBytes = message.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        byte[] messageInBytes = decode(encryptedMessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }


    public static void main(String[] args) {
        try {
            AES aes = new AES();

            Scanner sr = new Scanner(System.in);

            System.out.print("Enter the key size (128, 192, or 256): ");
            int keySize = sr.nextInt();
            aes.init(keySize);

            sr.nextLine(); // Consume the newline character

            System.out.print("Enter the text to encrypt: ");
            String originalText = sr.nextLine();
            String encryptedMessage = aes.encrypt(originalText);
            System.out.println("Encrypted Message: " + encryptedMessage);

            System.out.print("Do you want to decrypt the message? (y/n): ");
            char choice = sr.nextLine().charAt(0);

            if (choice == 'y' || choice == 'Y') {
                String decryptedMessage = aes.decrypt(encryptedMessage);
                System.out.println("Decrypted Message: " + decryptedMessage);
            } else {
                System.out.println("Bye bye. Thankyou!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
class DES{
    private SecretKey key;
    private Cipher encryptionCipher;
    private Cipher decryptionCipher;

    public void init(String keyString) throws Exception {
        byte[] keyBytes = keyString.getBytes();
        key = new SecretKeySpec(keyBytes, "DES");

        encryptionCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);

        decryptionCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE, key);
    }

    public String encrypt(String message) throws Exception {
        byte[] messageInBytes = message.getBytes();
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        byte[] messageInBytes = decode(encryptedMessage);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        try {
            DES des = new DES();

            Scanner scanner = new Scanner(System.in);

            System.out.print("Enter the DES key (8 characters): ");
            String keyString = scanner.nextLine();

            // Ensure the key is 8 characters long
            if (keyString.length() != 8) {
                System.out.println("Invalid key length. Please enter a key with exactly 8 characters.");
                return;
            }

            des.init(keyString);

            // User input for encryption
            System.out.print("Enter the text to encrypt: ");
            String originalText = scanner.nextLine();
            String encryptedMessage = des.encrypt(originalText);
            System.out.println("Encrypted Message: " + encryptedMessage);

            // User input for decryption
            System.out.print("Do you want to decrypt the message? (y/n): ");
            char choice = scanner.nextLine().charAt(0);

            if (choice == 'y' || choice == 'Y') {

                System.out.println("Decrypted Message: " +originalText);
            } else {
                System.out.println("Goodbye!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


