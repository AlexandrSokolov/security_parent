package com.savdev.jaas.jaxrs;

import javax.annotation.Resource;
import javax.annotation.security.RolesAllowed;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;

@Path(SimpleRestService.REST_SERVICE_URL)
@Stateless
@RolesAllowed("role1")
public class SimpleRestService {

    public static final String REST_SERVICE_URL = "/service";

    @Context
    private HttpServletRequest servletRequest;

    @Resource
    private javax.ejb.SessionContext sessionContext;

    @GET
    public String getResponse(){
        String response = "isUserInRole role1?" + servletRequest.isUserInRole("role1")
                + "</br>" + "getRemoteUser?" + servletRequest.getRemoteUser()
                + "</br>" + "getUserPrincipal?" + servletRequest.getUserPrincipal()
                + "</br>" + "getAuthType?" + servletRequest.getAuthType();
        String caller = sessionContext.getCallerPrincipal().getName();
        response += "</br>" + "sessionContext Principal name " + caller;
        //also available:
        sessionContext.isCallerInRole("role1");
        return response;
    }
}
