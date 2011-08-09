package org.apache.shindig.social.core.oauth2;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 
 * @author mgmarum
 *
 */
public abstract class AuthorizationGrantHandler {
  
    public abstract String getGrantType();
    
    public abstract void validateGrant(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAuth2Exception;
    

}
