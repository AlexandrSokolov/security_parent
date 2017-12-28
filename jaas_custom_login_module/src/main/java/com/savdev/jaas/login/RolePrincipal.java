package com.savdev.jaas.login;

import java.security.Principal;
import java.util.Objects;

public class RolePrincipal implements Principal, java.io.Serializable {
    final private String role;

    public RolePrincipal(final String role) {
        this.role = role;
    }

    @Override
    public String getName() {
        return role;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RolePrincipal that = (RolePrincipal) o;
        return Objects.equals(role, that.role);
    }

    @Override
    public int hashCode() {

        return Objects.hash(role);
    }

    @Override
    public String toString() {
        return this.getName();
    }

}
