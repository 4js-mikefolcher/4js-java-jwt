PACKAGE com.fourjs.JWTWrapper

IMPORT security
IMPORT util

IMPORT FGL com.fourjs.JWTWrapper.JWTInterface

PUBLIC TYPE JWTRecord RECORD
   username STRING ATTRIBUTES(json_name="sub"),
   sessionId STRING ATTRIBUTES(json_name="jti"),
   roles DYNAMIC ARRAY OF STRING,
   token STRING
END RECORD

PUBLIC FUNCTION (self JWTRecord) initWithUser(username STRING, roles DYNAMIC ARRAY OF STRING) RETURNS ()

   LET self.username = username
   CALL roles.copyTo(self.roles)
   LET self.sessionId = security.RandomGenerator.CreateUUIDString()
   LET self.token = NULL 

END FUNCTION #initWithUser

PUBLIC FUNCTION (self JWTRecord) initWithToken(token STRING) RETURNS ()

   IF JWTInterface.validateJWT(token) THEN
      VAR jsonObj util.JSONObject = JWTInterface.getJWTObj(token)
      IF jsonObj IS NOT NULL THEN
         CALL jsonObj.toFGL(self)
         LET self.token = token
         CASE jsonObj.getType("aud")
            WHEN "ARRAY"
               VAR jsonArray util.JSONArray = jsonObj.get("aud")
               CALL jsonArray.toFGL(self.roles)
            WHEN "STRING"
               LET self.roles[1] = jsonObj.get("aud")
         END CASE
      END IF
   END IF

END FUNCTION #initWithToken

PUBLIC FUNCTION (self JWTRecord) generateToken() RETURNS (BOOLEAN)

   IF NOT self.isReady() THEN
      RETURN FALSE
   END IF
   LET self.token = JWTInterface.createJWT(self.username, self.sessionId, self.roles) 
   IF self.token IS NULL THEN
      RETURN FALSE
   END IF

   RETURN TRUE

END FUNCTION #generateToken

PUBLIC FUNCTION (self JWTRecord) isValid() RETURNS (BOOLEAN)

   IF self.token IS NULL THEN
      RETURN FALSE
   END IF

   RETURN JWTInterface.validateJWT(self.token)

END FUNCTION #isValid

PUBLIC FUNCTION (self JWTRecord) isReady() RETURNS (BOOLEAN)

    IF self.username IS NULL OR self.sessionId IS NULL THEN
       RETURN FALSE
    END IF

    RETURN TRUE 

END FUNCTION #isReady

PUBLIC FUNCTION (self JWTRecord) isEmpty() RETURNS (BOOLEAN)

   IF NOT self.isReady() THEN
      RETURN TRUE
   END IF

   IF self.token IS NULL THEN
      RETURN TRUE
   END IF

   RETURN FALSE

END FUNCTION #isEmpty
