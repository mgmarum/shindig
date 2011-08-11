package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.social.opensocial.oauth.OAuth2DataStore;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthorizationCodeGrant extends AuthorizationGrantHandler {

  private OAuth2DataStore dataStore;

  public AuthorizationCodeGrant(OAuth2DataStore dataStore) {
    this.dataStore = dataStore;
  }

  @Override
  public String getGrantType() {
    return "authorization_code";
  }
  
  public void setDataStore(OAuth2DataStore store){
    dataStore = store;
  }

  @Override
  public void validateGrant(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
      throws OAuth2Exception {
    OAuth2ClientRegistration clientReg = dataStore.lookupClient(servletRequest.getParameter("client_id"));
    AuthorizationCode authCode = dataStore.retrieveAuthorizationCode(clientReg, servletRequest.getParameter("code"));
    String redirectURI = servletRequest.getParameter("redirect_uri");
    if(redirectURI == null || redirectURI.equals("")){
      throw new OAuth2Exception("Redirect URI required for Authorization Code grants");
    }
    if(authCode.getRedirectURI() != null && !authCode.getRedirectURI().equals(redirectURI)){
      throw new OAuth2Exception("Redirect URI does not match the one issued to this authorization code");
    }
    OAuth2Token atoken = dataStore.generateAccessToken(clientReg, authCode);
    transmitBearerToken(atoken, servletResponse);
    
  }

}
