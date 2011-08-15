package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.auth.AuthenticationHandler;
import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.social.opensocial.oauth.OAuth2DataStore;

import javax.servlet.http.HttpServletRequest;

import com.google.inject.Inject;

public class OAuth2AuthenticationHandler implements AuthenticationHandler {

  
  private OAuth2DataStore store;

  @Override
  public String getName() {
    return "OAuth2";
  }
  
  @Inject
  public OAuth2AuthenticationHandler(OAuth2DataStore store) {
    this.store = store;
  }

  /**
   * Only denies authentication when an invalid bearer token is received.  
   * Unauthenticated requests can pass through to other AuthenticationHandlers.
   */
  @Override
  public SecurityToken getSecurityTokenFromRequest(HttpServletRequest request)
      throws InvalidAuthenticationException {
    String bearer = OAuth2Utils.fetchBearerTokenFromHttpRequest(request);
    if(bearer != null){
      try{
        store.retrieveToken(bearer);
      }catch(OAuth2Exception ex){
        throw new InvalidAuthenticationException("Request contains invalid token", ex);
      }
    }
    return null;
  }

  @Override
  public String getWWWAuthenticateHeader(String realm) {
    return String.format("Bearer realm=\"%s\"", realm);
  }

}
