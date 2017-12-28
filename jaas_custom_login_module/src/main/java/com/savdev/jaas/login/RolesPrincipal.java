package com.savdev.jaas.login;

import com.google.common.collect.Sets;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/*
    This class accumulates a set of roles.
    In order to be considered as Principal for roles
    it must implement java.security.acl.Group; AND
        its name must be: "Roles"
        org.jboss.security.SecurityConstants.ROLES_IDENTIFIER = "Roles"

 */
public class RolesPrincipal implements Group, java.io.Serializable {

    public static final String rolesPrincipalName = "Roles";

    //set of RolePrincipal at runtime
    Set<Principal> roles = Sets.newHashSet();

    @Override
    public boolean addMember(Principal principal) {
        return roles.add(principal);
    }

    @Override
    public boolean removeMember(Principal principal) {
        return roles.remove(principal);
    }

    @Override
    public boolean isMember(Principal principal) {
        return roles.contains(principal);
    }

    @Override
    public Enumeration<? extends Principal> members() {
        return java.util.Collections.enumeration(roles);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RolesPrincipal that = (RolesPrincipal) o;
        return Objects.equals(roles, that.roles);
    }

    @Override
    public int hashCode() {
        return Objects.hash(roles);
    }

    @Override
    public String getName() {
        return rolesPrincipalName;
    }

    @Override
    public String toString() {
        return roles.stream()
                .map(Principal::getName)
                .collect(Collectors.joining(","));
    }
}
