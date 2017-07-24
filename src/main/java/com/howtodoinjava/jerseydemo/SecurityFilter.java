package com.howtodoinjava.jerseydemo;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.*;

/**
 * This filter verifies the access permissions for a user based on
 * the username and password provided in a request
 */
@Provider
public class SecurityFilter implements ContainerRequestFilter
{
    private static final String AUTHORIZATION_PROPERTY = "Authorization";
    private static final String AUTHENTICATION_SCHEME = "Basic";
    private static final Response ACCESS_DENIED = Response.status(Response.Status.UNAUTHORIZED).build();
    private static final Response ACCESS_FORBIDDEN = Response.status(Response.Status.FORBIDDEN).build();
    private static final Response SERVER_ERROR = Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();

    @Context
    private ResourceInfo resourceInfo;

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException
    {
        Method method = resourceInfo.getResourceMethod();
        //Access allowed for all
        if (!method.isAnnotationPresent(PermitAll.class))
        {
            // Access denied for all
            if (method.isAnnotationPresent(DenyAll.class)) {
                containerRequestContext.abortWith(ACCESS_FORBIDDEN);
            }

            // Get request headers
            final MultivaluedMap<String, String> headers = containerRequestContext.getHeaders();

            // Fetch authorization header
            final List<String> authorization = headers.get(AUTHORIZATION_PROPERTY);

            // If no authorization information is present, block access
            if (authorization == null || authorization.isEmpty()) {
                containerRequestContext.abortWith(ACCESS_DENIED);
                return;
            }

            // Get encoded username and password
            final String encodedUserPassword = authorization.get(0).replaceFirst(AUTHENTICATION_SCHEME + " ", "");

            // Decode username and password
            String usernameAndPassword = null;
            try {
                usernameAndPassword = new String(Base64.getDecoder().decode(encodedUserPassword));
            } catch (Exception e) {
                containerRequestContext.abortWith(SERVER_ERROR);
                return;
            }

            // Split username and password tokens
            final StringTokenizer tokenizer = new StringTokenizer(usernameAndPassword, ":");
            final String username = tokenizer.nextToken();
            final String password = tokenizer.nextToken();

            // Verifying Username and password
            if (!(username.equalsIgnoreCase("admin") && password.equalsIgnoreCase("password"))) {
                containerRequestContext.abortWith(ACCESS_DENIED);
                return;
            }

            // Verify user access
            if (method.isAnnotationPresent(RolesAllowed.class)) {
                RolesAllowed rolesAnnotation = method.getAnnotation(RolesAllowed.class);
                Set<String> rolesSet = new HashSet<>(Arrays.asList(rolesAnnotation.value()));

                // Is user valid?
                if (!isUserAllowed(username, password, rolesSet)) {
                    containerRequestContext.abortWith(ACCESS_DENIED);
                    return;
                }
            }
        }
    }

    private boolean isUserAllowed(final String username, final String password, final Set<String> rolesSet)
    {
        boolean isAllowed = false;

        // Step 1. Fetch password from database and match with password in argument
        // if both match: get the defined role for the user from the data base and continue
        // else:isAllowed = false
        // Access the database and do this part yourself;
        // String userRole = userMgr.getUserRole(username);
        String userRole = "ADMIN";

        // Step 2. Verify user role
        if (rolesSet.contains(userRole)) {
            isAllowed = true;
        }

        return isAllowed;
    }
}
