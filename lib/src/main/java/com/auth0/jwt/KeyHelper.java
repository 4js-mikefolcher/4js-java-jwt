package com.auth0.jwt;

import java.io.*;
import java.security.spec.*;
import java.security.*;
import java.nio.file.*;

/**
 * The KeyHelper class converts a private key file to a PrivateKey object and a
 * public key file to a PublicKey object.
 * <p>
 * Use getPrivateKey to convert a private key file to a PrivateKey object.
 * Use getPublicKey to convert a public key file to a PublicKey object.
 *
 */
public final class KeyHelper {

    /**
     * Test to Validate Key Files
     * <p>
     * This method will take a private key and public key and validate that the key
     * file can be used to instatiate a PrivateKey and PublicKey object.
     *
     * @param args String array with private key and public key files
     */
    public static void main(String[] args) {

        if (args.length < 2) {
            System.exit(-1);
        }

        String privateFile = args[0];
        String publicFile = args[1];

        try {

            PrivateKey privateKey = getPrivateKey(privateFile);       
            PublicKey publicKey = getPublicKey(publicFile);       

        } catch (Exception ex) {

            System.exit(-1);

        }

    }

    /**
     * Get PrivateKey Object from Private Key File
     * <p>
     * This method will create a PrivateKey object from a private key file.
     *
     * @param filename String containing the private key filename and path
     * @return PrivateKey object built from the file
     * @throws Exception if there is an exception with the PrivateKey
     *                   creation process
     */
    public static PrivateKey getPrivateKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * Get PublicKey Object from Public Key File
     * <p>
     * This method will create a PublicKey object from a public key file.
     *
     * @param filename String  containing the public key filename and path
     * @return PublicKey object built from the file
     * @throws Exception if there is an exception with the PublicKey
     *                   creation process
     */
    public static PublicKey getPublicKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);

    }
}
