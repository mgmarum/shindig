package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.auth.AuthenticationHandler;
import org.apache.shindig.auth.SecurityToken;

import javax.servlet.http.HttpServletRequest;

import com.google.inject.Inject;

public class OAuth2AuthenticationHandler implements AuthenticationHandler {

  
  private OAuth2Service store;

  @Override
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
  @Override
  public SecurityToken getSecurityTokenFromRequest(HttpServletRequest request)
      throws InvalidAuthenticationException {
    String bearer = OAuth2Utils.fetchBearerTokenFromHttpRequest(request);
    OAuth2NormalizedRequest req;
    try {
      req = new OAuth2NormalizedRequest(request);
      if(bearer != null){
        try{
          OAuth2Token token = store.retrieveAccessToken(req.getClientId(), bearer);
          if(token == null){
            throw new InvalidAuthenticationException("Access token does not exist", null);
          }
        }catch(OAuth2Exception ex){
          throw new InvalidAuthenticationException("Request contains invalid token", ex);
        }
      }
    } catch (OAuth2Exception e) {
      //Not a valid OAuth2 message??  Probably can't easily assume it was intended to be OAuth2.
    }
    return null;
  }

  @Override
  public String getWWWAuthenticateHeader(String realm) {
    return String.format("Bearer realm=\"%s\"", realm);
  }

}
