package org.apache.shindig.social.core.oauth2;


/**
 * 
 * @author mgmarum
 *
 */
public abstract class AuthorizationGrantHandler {
  
    public abstract String getGrantType();
    
    public abstract void validateGrant(OAuth2NormalizedRequest servletRequest) throws OAuth2Exception;
    

}
