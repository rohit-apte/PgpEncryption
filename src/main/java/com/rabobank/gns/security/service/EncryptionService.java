package com.rabobank.gns.security.service;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;

public class EncryptionService {

  private static String fileLocation =
      "D:/Rohit/WorkSpace/IdeaProjects/security/src/main/resources/files/";
  private static String plainTextFile = fileLocation + "plaintext.txt";
  private static String cipherTextFile = fileLocation + "cyphertext.txt.pgp";
  private static String privKeyFile = fileLocation + "privatekey.asc";
  private static String pubKeyFile = fileLocation + "publickey.asc";
  private static String decPlainTextFile = fileLocation + "decplaintext.txt";

  private static String id = "rohit";
  private static String passwd = "test@123";
  private static boolean isArmored = false;

  //  public static void encryptFile() throws Exception {
  ////    KeyBasedLargeFileProcessor.main(new String[] {"-e", fileToBeEncrypted, publickey, "asc"});
  //    PBEFileProcessor.main(new String[]{"-e", fileToBeEncrypted, "password"});
  //  }
  //
  //  public static void decryptFile() throws Exception {
  ////    KeyBasedLargeFileProcessor.main(new String[] {"-d", encryptedFile, pvtkey, "password"});
  //    PBEFileProcessor.main(new String[]{"-d", encryptedFile, "password"});
  //
  //  }

  public static void genKeyPair()
      throws NoSuchProviderException, IOException, PGPException, NoSuchAlgorithmException {

    Security.addProvider(new BouncyCastleProvider());

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

    kpg.initialize(1024);

    KeyPair kp = kpg.generateKeyPair();

    FileOutputStream out1 = new FileOutputStream(privKeyFile);
    FileOutputStream out2 = new FileOutputStream(pubKeyFile);

    exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), isArmored);
  }

  private static void exportKeyPair(
      OutputStream secretOut,
      OutputStream publicOut,
      PublicKey publicKey,
      PrivateKey privateKey,
      String identity,
      char[] passPhrase,
      boolean armor)
      throws IOException, PGPException {
    if (armor) {
      secretOut = new ArmoredOutputStream(secretOut);
    }

    PGPPublicKey a =
        (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey, new Date()));
    RSAPrivateCrtKey rsK = (RSAPrivateCrtKey) privateKey;
    RSASecretBCPGKey privPk =
        new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
    PGPPrivateKey b = new PGPPrivateKey(a.getKeyID(), a.getPublicKeyPacket(), privPk);

    PGPDigestCalculator sha1Calc =
        new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
    PGPKeyPair keyPair = new PGPKeyPair(a, b);
    PGPSecretKey secretKey =
        new PGPSecretKey(
            PGPSignature.DEFAULT_CERTIFICATION,
            keyPair,
            identity,
            sha1Calc,
            null,
            null,
            new JcaPGPContentSignerBuilder(
                keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc)
                .setProvider("BC")
                .build(passPhrase));

    secretKey.encode(secretOut);

    secretOut.close();

    if (armor) {
      publicOut = new ArmoredOutputStream(publicOut);
    }

    PGPPublicKey key = secretKey.getPublicKey();

    key.encode(publicOut);

    publicOut.close();
  }

  public static void encrypt() throws NoSuchProviderException, IOException, PGPException {
    FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
    FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
    PgpHelper.getInstance()
        .encryptFile(
            cipheredFileIs,
            plainTextFile,
            PgpHelper.getInstance().readPublicKey(pubKeyIs),
            isArmored,
            true);
    cipheredFileIs.close();
    pubKeyIs.close();
  }

  public static void decrypt() throws Exception {

    FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
    FileInputStream privKeyIn = new FileInputStream(privKeyFile);
    FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
    PgpHelper.getInstance()
        .decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
    cipheredFileIs.close();
    plainTextFileIs.close();
    privKeyIn.close();
  }
}
