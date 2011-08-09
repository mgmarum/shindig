package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.social.opensocial.oauth.OAuth2DataStore;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.inject.Inject;

public class AuthorizationCodeGrant extends AuthorizationGrantHandler {

  private OAuth2DataStore dataStore;

  @Override
  public String getGrantType() {
    return "authorization_code";
  }
  
  @Inject
  public void setDataStore(OAuth2DataStore store){
    dataStore = store;
  }

  @Override
  public void validateGrant(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
      throws OAuth2Exception {
    dataStore.validateAuthorizationCode(
        dataStore.getClient(servletRequest.getParameter("client_id")), 
        servletRequest.getParameter("code"));
    String redirectURI = servletRequest.getParameter("redirect_uri");
    if(redirectURI == null || redirectURI.equals("")){
      throw new OAuth2Exception("Redirect URI required for Authorization Code grants");
    }
  }

}
