package com.example.mycryptinbio.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

@Service
public class CryptoService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyPair keyPair;

    @jakarta.annotation.PostConstruct
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        generateKeyPair();
    }

    public void generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        keyPair = keyGen.generateKeyPair();
    }

    public void saveKeyPair(String privateKeyFile, String publicKeyFile) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(privateKeyFile)) {
            fos.write(keyPair.getPrivate().getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream(publicKeyFile)) {
            fos.write(keyPair.getPublic().getEncoded());
        }
    }

    public void loadKeyPair(String privateKeyFile, String publicKeyFile) throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(privateKeyFile));
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyFile));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        keyPair = new KeyPair(publicKey, privateKey);
    }

    public byte[] encryptFile(byte[] inputBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return cipher.doFinal(inputBytes);
    }

    public byte[] decryptFile(byte[] encryptedBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        return cipher.doFinal(encryptedBytes);
    }
}
