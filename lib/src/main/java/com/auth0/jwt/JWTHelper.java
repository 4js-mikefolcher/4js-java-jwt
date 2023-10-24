package com.auth0.jwt;

import java.util.Date;
import java.security.*;
import java.security.interfaces.*;
import java.util.ArrayList;

import com.auth0.jwt.JWT;
import com.auth0.jwt.KeyHelper;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.JWTDecoder;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

/**
 * The JWTHelper class helps create the JWT token.
 * <p>
 * Use getToken to create the JWT token.
 *
 */
public final class JWTHelper {

    /**
     * Test to Validate JWT Token.
     * <p>
     * Use to validate the JWT string created by getSimpleToken.
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

            RSAPrivateKey privateKey = (RSAPrivateKey) KeyHelper.getPrivateKey(privateFile);
            RSAPublicKey publicKey = (RSAPublicKey) KeyHelper.getPublicKey(publicFile);
            ArrayList<String> audience = new ArrayList<String>();
            audience.add("Role.User");

            Algorithm algo = Algorithm.RSA256(publicKey, privateKey);
            String token = JWTHelper.getSimpleToken(
                algo,
                60,
                "1234-56789-1234-ABCDE",
                "mike",
                audience.toArray(new String[audience.size()])
            );

        } catch (Exception ex) {

            System.exit(-1);

        }

    }

    /**
     * Get Simple JWT string.
     * <p>
     * This method will create a JWT string from the information passed to the method.
     *
     * @param algo encryption key algorithm object
     * @param expireMins number of minutes until the token expires
     * @param sessionId application session ID
     * @param subject Subject of the JWT
     * @param audience Audience of the JWT
     * @return JWT Token string
     * @throws Exception if there is an exception with the token
     *                   creation process
     */
    public static String getSimpleToken(
        Algorithm algo,
        int expireMins,
        String sessionId,
        String subject,
        String[] audience
    ) throws Exception {

        final long ONE_MINUTE_IN_MILLIS = 60000; 
        Date currentDate = new Date();                
        long currentTime  = currentDate.getTime();
        Date expireDate = new Date(currentTime + (expireMins * ONE_MINUTE_IN_MILLIS));

        String token = JWT.create()
            .withIssuer("fourjs-uscan")
            .withSubject(subject)
            .withAudience(audience)
            .withExpiresAt(expireDate)
            .withIssuedAt(currentDate)
            .withJWTId(sessionId)
            .sign(algo); 
        return token;
    }

    /**
     * Get JWT object from JWT string.
     * <p>
     * This method will builds and verifies a JWT object from the token string.
     *
     * @param algo encryption key algorithm object
     * @param token JWT Token string
     * @return A decoded JWT object
     * @throws Exception if there is an exception with the token
     *                   creation process
     */
    public static DecodedJWT getJWT(Algorithm algo, String token) throws Exception {

        DecodedJWT jwt;
        try {
            jwt = JWT.require(algo).build().verify(token);
        } catch (Exception ex) {
            jwt = null;
            throw ex;
        }
        return jwt; 

    }

}
