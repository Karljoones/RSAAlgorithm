package security.assignment.karl;

/**
 * Created by Karl on 21/03/2016.
 *
 * This class controls the encryption and the decryption of plaintext and of the files that are input into the system.
 *
 * To use:
 * Put plaintext files into the plainFiles/ directory, and the decrypted files in the encryptedFiles/ directory.
 */

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class RSA {
    // Bit length
    private static int bitlen = 128;

    /**
     * Encrypt the given plaintext message into ciphertext
     */
    public static String encrypt(String message, String e, String n) {
        // Take out the spaces, non-alphanumeric characters and put the string in lower case.
        String newMessage = message.replaceAll("\\s+", "");
        newMessage = newMessage.replaceAll("[^A-Za-z0-9]", "");
        newMessage = newMessage.toLowerCase();
        BigInteger m = new BigInteger(newMessage.getBytes()); // convert String to BigInteger for encryption
        BigInteger eB = new BigInteger(e, 16);// parse hex String to BigInteger
        BigInteger nB = new BigInteger(n, 16);// parse hex String to BigInteger
        BigInteger tmp, res = BigInteger.ZERO;
        int i = 0;
        while (!m.equals(BigInteger.ZERO)) {
			/* in this loop we encrypt every block
			 get remainder of the division, encrypt it, and add to encrypted variable,
			 then divide file variable into n and do the same thing, and add encrypted block
			 multiplied by n^i, where i is index of iteration*/
            tmp = m.mod(nB);
            res = res.add(modular_pow(tmp, eB, nB).multiply(nB.pow(i)));
            i++;
            m = m.divide(nB);
        }
        return res.toString(16);// encrypting and return hex String
    }

    /**
     * Decrypt the given ciphertext message into plaintext
     */
    public static String decrypt(String message, String d, String n) {
        BigInteger m = new BigInteger(message, 16); // parse hex String to BigInteger
        BigInteger dB = new BigInteger(d, 16);// parse hex String to BigInteger
        BigInteger nB = new BigInteger(n, 16);// parse hex String to BigInteger
        BigInteger tmp, res = BigInteger.ZERO;
        int i = 0;
        while (!m.equals(BigInteger.ZERO)) {
			/* in this loop we encrypt every block
			 get remainder of the division, encrypt it, and add to encrypted variable,
			 then divide file variable into n and do the same thing, and add encrypted block
			 multiplied by n^i, where i is index of iteration*/
            tmp = m.mod(nB);
            res = res.add(modular_pow(tmp, dB, nB).multiply(nB.pow(i)));
            i++;
            m = m.divide(nB);
        }
        return new String(res.toByteArray());
    }

    /**
     * Generate the public and the private keys.
     * @return BigInteger: keys
     */
    public static BigInteger[] generateKeys() {
        BigInteger n, d, e; // security.assignment.karl.RSA parameters
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r); // generate random p
        int certainty = 1000;
        while (!p.isProbablePrime(certainty)) {
            p = new BigInteger(bitlen / 2, 100, r); // if number is not probable
            // prime, generate new
            // number (probability that
            // number is prime is
            // (1-1/2^certainty)
        }
        BigInteger q = new BigInteger(bitlen / 2, 100, r); // generate random
        while (!q.isProbablePrime(certainty)) {
            q = new BigInteger(bitlen / 2, 100, r);
        }
        n = p.multiply(q); // n=p*q
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); // Euclidean Algorithm
        e = new BigInteger("3");
        while (gcd(m, e).intValue() > 1) { // find Coprime integer to m;
            e = e.add(new BigInteger("2"));
        }
        d = mul_inv(e, m); // calculate private key
        BigInteger[] out = { e, d, n };
        return out; // return Array of public key, private key and n;
    }

    /**
     * The multiplicative inverse.
     */
    private static BigInteger mul_inv(BigInteger a, BigInteger b) {

        BigInteger b0 = b, tmp, q;
        // we use q to remember quotient, tmp as temporary variable, b to remember initial value of b
        BigInteger x0 = BigInteger.ZERO, x1 = BigInteger.ONE;
        if (b.equals(BigInteger.ONE))
            return BigInteger.ONE;
        while (a.compareTo(BigInteger.ONE) > 0) {
            q = a.divide(b);
            tmp = b;
            b = a.mod(b);
            a = tmp;
            tmp = x0;
            x0 = x1.subtract(q.multiply(x0));
            x1 = tmp;
        }
        if (x1.compareTo(BigInteger.ZERO) < 0)
            x1 = x1.add(b0); // if result < 0, we can get it modulo ( (-a) mod n = n - a = (-a) + n)
        return x1;
    }

    /**
     * Get the mod of the BigInteger
     * @return BigInteger
     */
    private static BigInteger modular_pow(BigInteger b, BigInteger e, BigInteger m) {
        BigInteger x = new BigInteger("1"); // The default value of x
        BigInteger power;
        power = b.mod(m);
        String t = e.toString(2); // convert the power to string of binary
        String reverse = new StringBuffer(t).reverse().toString();
        for (int i = 0; i < reverse.length(); i++) { // this loop to go over the string char by char by reverse
            if (reverse.charAt(i) == '1') { // the start of if statement when the char is 1
                x = x.multiply(power);
                x = x.mod(m);
            }
            power = power.multiply(power);
            power = power.mod(m);
        }
        return x;
    }

    /**
     * Encrypt the file that it is given.
     * @param path : file path
     */
    public static BigInteger encryptFile(String path, String e, String n) throws IOException {
        String fileName = path; // save file name
        path = "plainFiles/" + path;// add directory name to the file path
        BigInteger eB = new BigInteger(e, 16); // parse hex String to BigInteger
        BigInteger nB = new BigInteger(n, 16);
        Path filePath = Paths.get(path);// create path to file
        BigInteger file = new BigInteger(Files.readAllBytes(filePath)); // generate BigInteger from byte array, which was got from file

        gui.setPlainTextTA("File contents:\n" + Files.readAllLines(filePath).toString());

        BigInteger encrypted = BigInteger.ZERO;
        BigInteger tmp;
        int i = 0;
        while (!file.equals(BigInteger.ZERO)) {
			/* in this loop we encrypt every block of file
			 get remainder of the division, encrypt it, and add to encrypted variable,
			 then divide file variable into n and do the same thing, and add encrypted block
			 multiplied by n^i, where i is index of iteration*/
            tmp = file.mod(nB);
            encrypted = encrypted.add(modular_pow(tmp, eB, nB).multiply(nB.pow(i)));
            i++;
            file = file.divide(nB);
        }

        // Write the encrypted message into a file in the encryptedFiles/ directory
        FileOutputStream fos = new FileOutputStream("encryptedFiles/" + fileName);
        fos.write(encrypted.toByteArray());
        fos.close();
        return encrypted;
    }

    /**
     * Decrypt the file
     * @throws IOException
     */
    public static void decryptFile(String path, String d, String n) throws IOException {
        String fileName = path;
        path = "encryptedFiles/" + path;
        BigInteger dB = new BigInteger(d, 16);
        BigInteger nB = new BigInteger(n, 16);
        Path filePath = Paths.get(path);
        BigInteger file = new BigInteger(Files.readAllBytes(filePath));
        gui.setCipherTextTA("File contents:\n" + Files.readAllBytes(filePath).toString());

        BigInteger decrypted = BigInteger.ZERO;
        BigInteger tmp;
        int i = 0;
        while (!file.equals(BigInteger.ZERO)) {
            tmp = file.mod(nB);
            decrypted = decrypted.add(modular_pow(tmp, dB, nB).multiply(nB.pow(i)));
            i++;
            file = file.divide(nB);
        }

        // Write plaintext back into plainFiles/ directory
        FileOutputStream fos = new FileOutputStream("plainFiles/" + fileName);
        fos.write(decrypted.toByteArray());
        fos.close();
    }

    /**
     * Get the greatest common divisor of two BigIntegers.
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO))
            return a;
        else
            return gcd(b, a.mod(b)); // when a divided into b, a mod b = 0, so a is gcd;
    }

    static GUI gui;

    public static void main(String[] args) throws IOException {
        // Initialise the security.assignment.karl.GUI.
        gui = new GUI();
    }
}
