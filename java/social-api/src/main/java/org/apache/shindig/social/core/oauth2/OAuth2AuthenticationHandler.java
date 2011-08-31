package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.auth.AnonymousSecurityToken;
import org.apache.shindig.auth.AuthenticationHandler;
import org.apache.shindig.auth.SecurityToken;

import javax.servlet.http.HttpServletRequest;

import com.google.inject.Inject;

public class OAuth2AuthenticationHandler implements AuthenticationHandler {

  
  private OAuth2Service store;

  public String getName() {
    return "OAuth2";
  }
  
  @Inject
  public OAuth2AuthenticationHandler(OAuth2Service store) {
    this.store = store;
  }

  /**
   * Only denies authentication when an invalid bearer token is received.  
   * Unauthenticated requests can pass through to other AuthenticationHandlers.
   */
  public SecurityToken getSecurityTokenFromRequest(HttpServletRequest request)
      throws InvalidAuthenticationException {
    OAuth2NormalizedRequest normalizedReq;
    try{
      normalizedReq = new OAuth2NormalizedRequest(request);
    }catch(OAuth2Exception oae){
      //May not have been a real OAuth2 request?
      return null;
    }
    try {
      if(normalizedReq.getAccessToken() != null){
        store.validateRequestForResource(normalizedReq, null);
        return new AnonymousSecurityToken();  //Return your valid security token
      }
    } catch (OAuth2Exception oae) {
      oae.printStackTrace();
      throw new InvalidAuthenticationException("Something went wrong: ", oae); // TODO: process OAuth2Exception
    }
    return null;
  }

  public String getWWWAuthenticateHeader(String realm) {
    return String.format("Bearer realm=\"%s\"", realm);
  }

}
