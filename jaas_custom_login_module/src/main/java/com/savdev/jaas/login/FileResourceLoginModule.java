package com.savdev.jaas.login;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Map;
import java.util.Set;

public class FileResourceLoginModule implements LoginModule {

    private static final Log log = LogFactory.getLog(FileResourceLoginModule.class);

    //TODO refactore to take it from a file
    static Map<String, String> login2pwd = ImmutableMap.of(
            "testUser1", "pwd1",
            "testUser2", "pwd2"
    );

    static Map<String, Set<String>> login2roles = ImmutableMap.of(
            "testUser1", Sets.newHashSet("admin","role1"),
            "testUser2", Sets.newHashSet("role2")
    );

    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map options;

    // the authentication status
    private boolean loginSucceeded = false;
    private boolean commitSucceeded = false;

    // username and password
    private String username;
    private String password;

    // testUser's SamplePrincipal
    private LoginPrincipal loginPrincipal;

    /**
     * Initialize this <code>LoginModule</code>.
     * <p>
     * <p>
     *
     * @param subject         the <code>Subject</code> to be authenticated. <p>
     * @param callbackHandler a <code>CallbackHandler</code> for communicating
     *                        with the end user (prompting for user names and
     *                        passwords, for example). <p>
     * @param sharedState     shared <code>LoginModule</code> state. <p>
     * @param options         options specified in the login
     *                        <code>Configuration</code> for this particular
     *                        <code>LoginModule</code>.
     */
    public void initialize(Subject subject,
                           CallbackHandler callbackHandler,
                           Map<java.lang.String, ?> sharedState,
                           Map<java.lang.String, ?> options) {

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;

    }

    /**
     * Authenticate the user by prompting for a user name and password.
     * <p>
     * <p>
     *
     * @return true in all cases since this <code>LoginModule</code>
     * should not be ignored.
     * @throws FailedLoginException if the authentication fails. <p>
     * @throws LoginException       if this <code>LoginModule</code>
     *                              is unable to perform the authentication.
     */
    public boolean login() throws LoginException {

        // prompt for a user name and password
        if (callbackHandler == null)
            throw new LoginException("Error: no CallbackHandler available " +
                    "to garner authentication information from the user");

        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("user name: ");
        callbacks[1] = new PasswordCallback("password: ", false);

        try {
            callbackHandler.handle(callbacks);
            username = ((NameCallback) callbacks[0]).getName();
            char[] tmpPassword = ((PasswordCallback) callbacks[1]).getPassword();
            if (tmpPassword == null) {
                // treat a NULL password as an empty password
                tmpPassword = new char[0];
            }
            password = new String(tmpPassword);
            ((PasswordCallback) callbacks[1]).clearPassword();

        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.toString());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException("Error: " + uce.getCallback().toString() +
                    " not available to garner authentication information " +
                    "from the user");
        }

        // print debugging information
        log.debug("\t\t[FileResourceLoginModule] " +
                "user entered user name: " +
                username);

        //verify the username/password
        //additionally we should search for roles,
        //but here  we get it from map
        if (login2pwd.containsKey(username)){
            if (password.equals(login2pwd.get(username))){
                loginSucceeded = true;
                log.debug("\t\t[FileResourceLoginModule] " +
                        "authentication loginSucceeded");
                return true;
            } else {
                throw new FailedLoginException("Password Incorrect");
            }
        } else {
            throw new FailedLoginException("User Name Incorrect");
        }
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication loginSucceeded
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
     * loginSucceeded).
     * <p>
     * <p> If this LoginModule's own authentication attempt
     * loginSucceeded (checked by retrieving the private state saved by the
     * <code>login</code> method), then this method associates a
     * <code>LoginPrincipal</code>
     * with the <code>Subject</code> located in the
     * <code>LoginModule</code>.  If this LoginModule's own
     * authentication attempted failed, then this method removes
     * any state that was originally saved.
     * <p>
     * <p>
     *
     * @return true if this LoginModule's own login and commit
     * attempts loginSucceeded, or false otherwise.
     * @throws LoginException if the commit fails.
     */
    public boolean commit() throws LoginException {
        if (loginSucceeded == false) {
            return false;
        } else {
            // add a Principal (authenticated identity)
            // to the Subject

            // assume the user we authenticated is the SamplePrincipal
            loginPrincipal = new LoginPrincipal(username);
            if (!subject.getPrincipals().contains(loginPrincipal))
                subject.getPrincipals().add(loginPrincipal);
            if (login2roles.containsKey(username)){
                RolesPrincipal rsp = new RolesPrincipal();
                login2roles.get(username).forEach(r -> {
                    rsp.addMember(new RolePrincipal(r));
                });
                subject.getPrincipals().add(rsp);
            } else {
                throw new IllegalStateException(
                        "Could not find a role for user = " + username);
            }


            log.debug("\t\t[FileResourceLoginModule] " +
                        "added SamplePrincipal to Subject");

            // in any case, clean out state
            username = null;
            password = null;

            commitSucceeded = true;
            return true;
        }
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication failed.
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
     * did not succeed).
     * <p>
     * <p> If this LoginModule's own authentication attempt
     * loginSucceeded (checked by retrieving the private state saved by the
     * <code>login</code> and <code>commit</code> methods),
     * then this method cleans up any state that was originally saved.
     * <p>
     * <p>
     *
     * @return false if this LoginModule's own login and/or commit attempts
     * failed, and true otherwise.
     * @throws LoginException if the abort fails.
     */
    public boolean abort() throws LoginException {
        if (loginSucceeded == false) {
            return false;
        } else if (loginSucceeded == true && commitSucceeded == false) {
            // login loginSucceeded but overall authentication failed
            loginSucceeded = false;
            username = null;
            password = null;
            loginPrincipal = null;
        } else {
            // overall authentication loginSucceeded and commit loginSucceeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    /**
     * Logout the user.
     * <p>
     * <p> This method removes the <code>SamplePrincipal</code>
     * that was added by the <code>commit</code> method.
     * <p>
     * <p>
     *
     * @return true in all cases since this <code>LoginModule</code>
     * should not be ignored.
     * @throws LoginException if the logout fails.
     */
    public boolean logout() throws LoginException {

        subject.getPrincipals().remove(loginPrincipal);
        loginSucceeded = false;
        commitSucceeded = false ;
        username = null;
        password = null;
        loginPrincipal = null;
        return true;
    }
}
