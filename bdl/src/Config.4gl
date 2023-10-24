PACKAGE com.fourjs.JWTWrapper

IMPORT JAVA com.auth0.jwt.KeyHelper
IMPORT JAVA java.security.PublicKey
IMPORT JAVA java.security.PrivateKey
IMPORT JAVA java.security.interfaces.RSAPublicKey
IMPORT JAVA java.security.interfaces.RSAPrivateKey

PUBLIC TYPE KeyHelper com.auth0.jwt.KeyHelper
PUBLIC TYPE RSAPublicKey java.security.interfaces.RSAPublicKey
PUBLIC TYPE RSAPrivateKey java.security.interfaces.RSAPrivateKey

PRIVATE CONSTANT cProfilePrivateKey = "jwt.private.key"
PRIVATE CONSTANT cEnvironmentPrivateKey = "JWT_PRIVATE_KEY"
PRIVATE DEFINE privateKeyFile STRING
PUBLIC FUNCTION getPrivateKeyFile() RETURNS (STRING)

   LET privateKeyFile = getStoredValue(privateKeyFile, cEnvironmentPrivateKey, cProfilePrivateKey)
   RETURN privateKeyFile

END FUNCTION #getPrivateKeyFile

PRIVATE CONSTANT cProfilePublicKey = "jwt.public.key"
PRIVATE CONSTANT cEnvironmentPublicKey = "JWT_PUBLIC_KEY"
PRIVATE DEFINE publicKeyFile STRING
PUBLIC FUNCTION getPublicKeyFile() RETURNS (STRING)

   LET publicKeyFile = getStoredValue(publicKeyFile, cEnvironmentPublicKey, cProfilePublicKey)
   RETURN publicKeyFile

END FUNCTION #getPublicKeyFile

PRIVATE CONSTANT cProfileExpireMins = "jwt.expire.mins"
PRIVATE CONSTANT cEnvironmentExpireMins = "JWT_EXPIRE_MINS"
PRIVATE DEFINE expireMins INTEGER = NULL
PUBLIC FUNCTION getExpireMins() RETURNS (INTEGER)

   VAR expireStr STRING = expireMins
   LET expireStr = getStoredValue(expireStr, cEnvironmentExpireMins, cProfileExpireMins)
   IF expireStr IS NOT NULL THEN
      LET expireMins = expireStr
   END IF
   RETURN expireMins

END FUNCTION #getExpireMins

PRIVATE FUNCTION getStoredValue(initialValue STRING, envName STRING, prfKey STRING) RETURNS STRING

   VAR getValue = initialValue

   IF getValue IS NOT NULL THEN
      RETURN getValue
   END IF

   #Environment variable will always take precedence over fglprofile
   LET getValue = FGL_GETENV(envName)
   IF getValue IS NOT NULL THEN
      RETURN getValue
   END IF

   #If the getValue is still empty, use the fglprofile entry
   LET getValue = base.Application.getResourceEntry(prfKey)
   RETURN getValue

END FUNCTION #getStoredValue

PRIVATE DEFINE privateKeyObj RSAPrivateKey
PUBLIC FUNCTION getPrivateKeyObj() RETURNS (RSAPrivateKey)

   IF privateKeyObj IS NOT NULL THEN
      RETURN privateKeyObj
   END IF

   LET privateKeyObj = CAST(KeyHelper.getPrivateKey(getPrivateKeyFile()) AS RSAPrivateKey)
   RETURN privateKeyObj

END FUNCTION #getPrivateKeyObj

PRIVATE DEFINE publicKeyObj RSAPublicKey
PUBLIC FUNCTION getPublicKeyObj() RETURNS (RSAPublicKey)

   IF publicKeyObj IS NOT NULL THEN
      RETURN publicKeyObj
   END IF

   LET publicKeyObj = CAST(KeyHelper.getPublicKey(getPublicKeyFile()) AS RSAPublicKey)
   RETURN publicKeyObj

END FUNCTION #getPublicKeyObj
