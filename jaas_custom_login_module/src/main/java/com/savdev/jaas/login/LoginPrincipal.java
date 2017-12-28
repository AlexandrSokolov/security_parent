package com.savdev.jaas.login;

import java.security.Principal;
import java.util.Objects;

public class LoginPrincipal implements Principal, java.io.Serializable {

    /**
     * @serial
     */
    private String name;

    public LoginPrincipal(final String name) {
        if (name == null)
            throw new NullPointerException("illegal null input");
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LoginPrincipal that = (LoginPrincipal) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {

        return Objects.hash(name);
    }

    @Override
    public String toString() {
        return this.getName();
    }
}
