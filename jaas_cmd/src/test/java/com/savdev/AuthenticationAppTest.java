package com.savdev;

import org.junit.Test;

public class AuthenticationAppTest {

    @Test
    public void testCorrectAuthenticate() {
        AuthenticationApp app = new AuthenticationApp();
        MyCallbackHandler myCallbackHandler =
                new MyCallbackHandler("testUser", "testPassword");
        app.authenticate(myCallbackHandler);
    }

    @Test(expected = RuntimeException.class)
    public void testWrongLoginAuthenticate() {
        AuthenticationApp app = new AuthenticationApp();
        MyCallbackHandler myCallbackHandler =
                new MyCallbackHandler("testUserWrong", "");
        app.authenticate(myCallbackHandler);
    }

    @Test(expected = RuntimeException.class)
    public void testWrongPwdAuthenticate() {
        AuthenticationApp app = new AuthenticationApp();
        MyCallbackHandler myCallbackHandler =
                new MyCallbackHandler("testUser", "wrongPwd");
        app.authenticate(myCallbackHandler);
    }
}
