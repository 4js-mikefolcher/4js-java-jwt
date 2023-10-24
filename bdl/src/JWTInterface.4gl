PACKAGE com.fourjs.JWTWrapper

IMPORT security
IMPORT util

IMPORT JAVA com.auth0.jwt.JWT
IMPORT JAVA com.auth0.jwt.algorithms.Algorithm
IMPORT JAVA com.auth0.jwt.KeyHelper
IMPORT JAVA com.auth0.jwt.JWTHelper
IMPORT JAVA com.auth0.jwt.interfaces.DecodedJWT
IMPORT JAVA java.security.PublicKey
IMPORT JAVA java.security.PrivateKey
IMPORT JAVA java.security.interfaces.RSAPublicKey
IMPORT JAVA java.security.interfaces.RSAPrivateKey
IMPORT JAVA java.lang.String

IMPORT FGL com.fourjs.JWTWrapper.Config

PUBLIC TYPE JavaJWT com.auth0.jwt.JWT
PUBLIC TYPE JWTHelper com.auth0.jwt.JWTHelper
PUBLIC TYPE KeyHelper com.auth0.jwt.KeyHelper
PUBLIC TYPE RSAPublicKey java.security.interfaces.RSAPublicKey
PUBLIC TYPE RSAPrivateKey java.security.interfaces.RSAPrivateKey
PUBLIC TYPE DecodedJWT com.auth0.jwt.interfaces.DecodedJWT

PUBLIC TYPE JavaStringArray ARRAY[] OF java.lang.String

PRIVATE DEFINE tokenCache DICTIONARY OF util.JSONObject

PUBLIC FUNCTION createJWT(username STRING, sessionId STRING, roles DYNAMIC ARRAY OF STRING) RETURNS (STRING)

   VAR expireMins = Config.getExpireMins()
   VAR pubKey = Config.getPublicKeyObj()
   VAR privKey = Config.getPrivateKeyObj() 

   VAR len = roles.getLength()
   VAR audience = JavaStringArray.create(len)
   VAR idx = 0
   FOR idx = 1 TO len
      LET audience[idx] = roles[idx]
   END FOR

   VAR algorithm = Algorithm.RSA256(pubKey, privKey);
   VAR token STRING = JWTHelper.getSimpleToken(algorithm, expireMins, sessionId, username, audience)

   RETURN token

END FUNCTION #createJWT()

PUBLIC FUNCTION validateJWT(token STRING) RETURNS (BOOLEAN)
   DEFINE jwtObj DecodedJWT

   VAR pubKey = Config.getPublicKeyObj()
   VAR privKey = Config.getPrivateKeyObj() 

   VAR algorithm = Algorithm.RSA256(pubKey, privKey);
   LET jwtObj = JWTHelper.getJWT(algorithm, token)

   IF jwtObj IS NULL THEN
      CALL tokenCache.remove(token)
      RETURN FALSE
   END IF

   VAR baseString STRING = jwtObj.getPayload()
   VAR offset INTEGER = baseString.getLength() MOD 4
   VAR idx = 0
   FOR idx = 1 TO offset
      LET baseString = baseString.append("=")
   END FOR
   VAR jsonString = security.Base64.ToString(baseString)
   VAR jsonObj = util.JSONObject.parse(jsonString)
   LET tokenCache[token] = jsonObj

   RETURN TRUE

END FUNCTION #validateJWT

PUBLIC FUNCTION getJWTObj(token STRING) RETURNS util.JSONObject
   DEFINE jsonObj util.JSONObject

   IF tokenCache.contains(token) THEN
      #Only return JSONObjects that have been validated
      LET jsonObj = tokenCache[token] 
   END IF
   RETURN jsonObj

END FUNCTION #getJWTObj

PUBLIC FUNCTION testing() RETURNS ()
   DEFINE myJWT JavaJWT
   DEFINE pubKey RSAPublicKey
   DEFINE privKey RSAPrivateKey
   DEFINE audience JavaStringArray
   DEFINE jwtObj DecodedJWT

   TRY 

      LET privKey = CAST(KeyHelper.getPrivateKey("private_key.der") AS RSAPrivateKey)
      LET pubKey = CAST(KeyHelper.getPublicKey("public_key.der") AS RSAPublicKey)

      DISPLAY privKey.getAlgorithm()
      DISPLAY privKey.getEncoded()
      DISPLAY privKey.getFormat()

      DISPLAY pubKey.getAlgorithm()
      DISPLAY pubKey.getEncoded()
      DISPLAY pubKey.getFormat()

      LET audience = JavaStringArray.create(2)
      LET audience[1] = "Role.User"
      LET audience[2] = "Role.Admin"

      VAR sessionId = security.RandomGenerator.CreateUUIDString()
      VAR expireMins = 60

      DISPLAY "Generating token"
      VAR algorithm = Algorithm.RSA256(pubKey, privKey);
      #VAR token STRING = JWTHelper.getSimpleToken(algorithm, "mike", audience)
      VAR token STRING = JWTHelper.getSimpleToken(algorithm, expireMins, sessionId, "mike", audience)
      DISPLAY SFMT("Token: %1", token)

      DISPLAY "Verifying token"
      LET jwtObj = JWTHelper.getJWT(algorithm, token)
      IF jwtObj IS NULL THEN
         DISPLAY "JWT is invalid!!!!"
      ELSE
         DISPLAY "JWT is valid"
         DISPLAY SFMT("Subject: %1", jwtObj.getSubject())
         DISPLAY SFMT("Expiration: %1", jwtObj.getExpiresAt())
         DISPLAY SFMT("Issued: %1", jwtObj.getIssuedAt())
         DISPLAY SFMT("Session ID: %1", jwtObj.getId())
         DISPLAY SFMT("Payload: %1", jwtObj.getPayload())
      END IF
       

   CATCH
      #Invalid Signing configuration / Couldn't convert Claims.
      DISPLAY SFMT("Error Code: %1", status)
      DISPLAY SFMT("Error Message: %1", sqlca.sqlerrm)
      DISPLAY "Kaboom!!!!"
   END TRY

END FUNCTION #testing

