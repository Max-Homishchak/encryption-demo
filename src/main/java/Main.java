import exceptions.YesOrNoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    private static final String SALT = "O(Wk3Gnv?AN-G5rpeO";
    private static final String IV_PARAM = "qv6lQnodjKupgG+AkciClA==";
    private static final String RSA = "RSA";
    private static final String AES = "AES";

    public static void main(String[] args) throws Exception {

        Scanner s = new Scanner(System.in);

        init(s);
    }

    private static void init(Scanner s) throws Exception{
        System.out.println("Dou u want to create new Private Key?\n" +
                "Y/N/S(Stop program)");

        String toCreateNewPrivateKey = s.nextLine().toUpperCase();

        try{
            if(toCreateNewPrivateKey.equals("Y")) {
                createPrivateKeyProcess(s);
            }else if(toCreateNewPrivateKey.equals("N")) {
                try{
                    readPrivateKeyProcess(s);
                }catch(BadPaddingException bde) {
                    System.out.println("Error = " + bde.getMessage() + "\ntry again");
                    init(s);
                }catch(NoSuchFileException nsfe) {
                    System.out.println("Error = " + nsfe.toString() + "\ntry again");
                    init(s);
                }
            }else if(!toCreateNewPrivateKey.equals("S")){
                throw new YesOrNoException("Incorrect response : " + toCreateNewPrivateKey);
            }
        }catch(YesOrNoException e){
            System.out.println("Error = " + e.getMessage() + "\ntry again!");
            init(s);
        }

    }

    private static void createPrivateKeyProcess(Scanner s) throws Exception{

        System.out.println("\nEnter name of file u want to create:");
        String fileName = s.nextLine();

        Console console = System.console();
        char[] givenPassword = console.readPassword("Enter password : ");

        String password = new String(givenPassword);

        PrivateKey privateKey = generatePrivateKey();
        Cipher c = getCipher(password, 1);
        saveEncryptedPrivateKey(fileName, privateKey, c);

        System.out.println("\nPrivateKey was successfully created and encrypted");
    }

    private static void readPrivateKeyProcess(Scanner s) throws Exception{

        System.out.println("\nEnter path to your private key + name of key:");
        String path = s.nextLine();

        Console console = System.console();
        char[] password = console.readPassword("Enter password : ");

        Cipher c = getCipher(new String(password), 2);

        PrivateKey privateKey;

        privateKey = decryptPrivateKey(path, c);

        System.out.println("\nU have successfully decrypted private key and now able to use it");

        toEncryptOrToDecrypt(s, privateKey);
    }

    private static void toEncryptOrToDecrypt(Scanner s, PrivateKey privateKey) throws Exception {

        while(true) {
            System.out.println("Choose action:\n1 - To Encrypt\n2 - To Decrypt\n3 - Show my public key\n4 - Stop");

            String userResponse = s.nextLine();

            if(userResponse.equals("1")) {
                encryptMessageForm(s);
            }else if(userResponse.equals("2")) {
                decryptMessageForm(s, privateKey);
            }else if(userResponse.equals("3")) {
                printPublicKey(privateKey);
            }else if(userResponse.equals("4")) {
                break;
            }
        }
    }

    private static void printPublicKey(PrivateKey privateKey) throws Exception{

        RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privateKey;

        RSAPublicKeySpec publicKeySpec1 = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());

        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        PublicKey myPublicKey = keyFactory.generatePublic(publicKeySpec1);

        String base64PublicKey = Base64.getEncoder().encodeToString(myPublicKey.getEncoded());

        System.out.println("\nYour public key = " + base64PublicKey);
    }

    private static void encryptMessageForm(Scanner s) throws Exception{

        KeyFactory keyFactory = KeyFactory.getInstance(RSA);

        System.out.println("\nEnter public key whom you want to send a message:");
        String pubKey = s.nextLine();
        byte[] publicKeyBytes = Base64.getDecoder().decode(pubKey);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        PublicKey pk = keyFactory.generatePublic(publicKeySpec);

        System.out.println("Message:");
        String message = s.nextLine();

        byte[] encryptedMessage = encryptMessage(message, pk);
        String base64Message = Base64.getEncoder().encodeToString(encryptedMessage);
        System.out.println("Encrypted Message = " + base64Message);
    }

    private static void decryptMessageForm(Scanner s, PrivateKey privateKey) throws Exception{

        System.out.println("\nEnter encrypted message");
        byte[] encryptedMessage = Base64.getDecoder().decode(s.nextLine());

        String decryptedMessage = decryptMessage(encryptedMessage, privateKey);

        System.out.println("Message: " + decryptedMessage);
    }

    /**
     * @param mode use 1 for Encryption, and 2 for Decryption
     */
    private static Cipher getCipher(String password, int mode) throws Exception{

        String result = SALT + password + SALT;
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] raw = digest.digest(result.getBytes("utf8"));

        SecretKeySpec skeySpec = new SecretKeySpec(raw, AES);

        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(IV_PARAM));

        cipher.init(mode, skeySpec, iv);

        return cipher;
    }

    private static PrivateKey generatePrivateKey() throws NoSuchAlgorithmException {

        SecureRandom secureRandom = new SecureRandom();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);

        keyPairGenerator.initialize(2048, secureRandom);

        PrivateKey privateKey = keyPairGenerator.generateKeyPair().getPrivate();

        return privateKey;
    }

    private static byte[] saveEncryptedPrivateKey(String keyFile, PrivateKey privateKey, Cipher cipher) throws Exception {

        byte[] encryptedPrivateKey = cipher.doFinal(privateKey.getEncoded());

        try(FileOutputStream out = new FileOutputStream(keyFile)) {
            out.write(encryptedPrivateKey);
        }

        return encryptedPrivateKey;
    }

    private static PrivateKey decryptPrivateKey(String keyFile, Cipher cipher) throws Exception{

        byte[] encryptedPrivateKey = Files.readAllBytes(Paths.get(keyFile));

        byte[] privateKeyBytes = cipher.doFinal(encryptedPrivateKey) ;

        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        return keyFactory.generatePrivate(privateKeySpec);
    }

    static public byte[] encryptMessage(String message, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance(RSA);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(message.getBytes());
    }

    static public String decryptMessage(byte[] encodedMessage, PrivateKey privateKey) throws Exception{

        Cipher cipher = Cipher.getInstance(RSA);

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(encodedMessage));
    }
}
