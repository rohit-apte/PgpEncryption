package com.rabobank.gns.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static com.rabobank.gns.security.service.EncryptionService.*;

@SpringBootApplication
public class SecurityApplication {

  public static void main(String[] args) throws Exception {
    SpringApplication.run(SecurityApplication.class, args);
    genKeyPair();
    System.out.println("key pair generated");
//    encrypt();
//    System.out.println("encryption done");
//    decrypt();
//    System.out.println("decryption done");
  }
}
