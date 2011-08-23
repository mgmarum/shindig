package org.apache.shindig.social.core.oauth2;


public class AuthCodeGrantValidator implements OAuth2GrantValidator {

  private OAuth2DataService service;

  public AuthCodeGrantValidator(OAuth2DataService service) {
    this.service = service;
  }

  @Override
  public String getGrantType() {
    return "authorization_code";
  }

  @Override
  public void validateRequest(OAuth2NormalizedRequest servletRequest) throws OAuth2Exception {
    OAuth2Code authCode = service.getAuthorizationCode(servletRequest.getClientId(), servletRequest.getAuthorizationCode());
    if(authCode == null){
      throw new OAuth2Exception("Bad authorization code");
    }
    String redirectURI = servletRequest.getString("redirect_uri");
    if(redirectURI == null || redirectURI.equals("")){
      throw new OAuth2Exception("Redirect URI required for Authorization Code grants");
    }
    if(authCode.getRedirectUri() != null && !authCode.getRedirectUri().equals(redirectURI)){
      throw new OAuth2Exception("Redirect URI does not match the one issued to this authorization code");
    }
  }

}
