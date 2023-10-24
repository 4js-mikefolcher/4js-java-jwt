IMPORT util
IMPORT FGL com.fourjs.JWTWrapper.JWTRecord

MAIN
   DEFINE roles DYNAMIC ARRAY OF STRING

   LET roles[1] = "Roles.User"
   CALL testWrapper("mike.folcher", roles)

   LET roles[2] = "Roles.Admin"
   CALL testWrapper("mifo", roles)

   CALL roles.clear()
   CALL testWrapper("michael.folcher", roles)

END MAIN

PRIVATE FUNCTION testWrapper(username STRING, roles DYNAMIC ARRAY OF STRING) RETURNS ()
   DEFINE myJWT JWTRecord

   CALL myJWT.initWithUser(username, roles)
   IF myJWT.generateToken() THEN
      IF myJWT.isValid() THEN
         DISPLAY "My JWT IS valid"
         VAR secondJWT JWTRecord
         CALL secondJWT.initWithToken(myJWT.token)
         DISPLAY SFMT("JWTRecord: %1", util.JSON.format(util.JSONObject.fromFGL(secondJWT).toString()))
      ELSE
         DISPLAY "My JWT is NOT valid"
      END IF
   ELSE
      DISPLAY "Failed to generate the token"
   END IF

END FUNCTION #testWrapper
