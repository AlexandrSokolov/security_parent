package com.savdev;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

public class AuthenticationApp {

    public void authenticate(MyCallbackHandler callbackHandler) {
        // Obtain a LoginContext, needed for authentication. Tell it
        // to use the LoginModule implementation specified by the
        // entry named "Sample" in the JAAS login configuration
        // file and to also use the specified CallbackHandler.
        LoginContext lc = null;
        try {
            lc = new LoginContext("Sample", callbackHandler);
        } catch (LoginException le) {
            System.err.println("Cannot create LoginContext. "
                    + le.getMessage());
            System.exit(-1);
        } catch (SecurityException se) {
            System.err.println("Cannot create LoginContext. "
                    + se.getMessage());
            System.exit(-1);
        }

        try {
            // attempt authentication
            lc.login();
        } catch (LoginException le) {
            System.err.println("Authentication failed:");
            System.err.println("  " + le.getMessage());
            throw new RuntimeException("Sorry, could not authenticate");
        }

        System.out.println("Authentication succeeded!");
    }
}
