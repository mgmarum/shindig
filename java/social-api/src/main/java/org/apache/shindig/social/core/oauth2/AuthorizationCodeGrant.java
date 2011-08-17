package org.apache.shindig.social.core.oauth2;


public class AuthorizationCodeGrant extends AuthorizationGrantHandler {

  private OAuth2Service service;

  public AuthorizationCodeGrant(OAuth2Service service) {
    this.service = service;
  }

  @Override
  public String getGrantType() {
    return "authorization_code";
  }
  
  public void setService(OAuth2Service service){
    this.service = service;
  }

  @Override
  public void validateGrant(OAuth2NormalizedRequest servletRequest) throws OAuth2Exception {
    OAuth2Code authCode = service.retrieveAuthCode(servletRequest.getClientId(), servletRequest.getString("code"));
    String redirectURI = servletRequest.getString("redirect_uri");
    if(redirectURI == null || redirectURI.equals("")){
      throw new OAuth2Exception("Redirect URI required for Authorization Code grants");
    }
    if(authCode.getRedirectUri() != null && !authCode.getRedirectUri().equals(redirectURI)){
      throw new OAuth2Exception("Redirect URI does not match the one issued to this authorization code");
    }
  }

}
