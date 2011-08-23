package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.social.core.oauth2.OAuth2Client.Flow;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;

import com.google.inject.Inject;


public class AuthCodeGrantValidator implements OAuth2GrantValidator {

  private OAuth2DataService service;

  @Inject
  public AuthCodeGrantValidator(OAuth2DataService service) {
    this.service = service;
  }

  @Override
  public String getGrantType() {
    return "authorization_code";
  }

  @Override
  public void validateRequest(OAuth2NormalizedRequest servletRequest) throws OAuth2Exception {
    OAuth2Client client = service.getClient(servletRequest.getClientId());
    if(client == null || client.getFlow() != Flow.AUTHORIZATION_CODE){
      throw new OAuth2Exception(ErrorType.INVALID_CLIENT,"Invalid Client");
    }
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
