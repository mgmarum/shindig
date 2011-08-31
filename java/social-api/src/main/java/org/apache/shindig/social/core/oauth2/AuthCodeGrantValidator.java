package org.apache.shindig.social.core.oauth2;

import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.social.core.oauth2.OAuth2Client.Flow;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;

import com.google.inject.Inject;


public class AuthCodeGrantValidator implements OAuth2GrantValidator {

  private OAuth2DataService service;

  @Inject
  public AuthCodeGrantValidator(OAuth2DataService service) {
    this.service = service;
  }

  public String getGrantType() {
    return "authorization_code";
  }

  public void validateRequest(OAuth2NormalizedRequest servletRequest) throws OAuth2Exception {
    OAuth2Client client = service.getClient(servletRequest.getClientId());
    if(client == null || client.getFlow() != Flow.AUTHORIZATION_CODE){
      throw new OAuth2Exception(ErrorType.INVALID_CLIENT,"Invalid Client");
    }
    OAuth2Code authCode = service.getAuthorizationCode(servletRequest.getClientId(), servletRequest.getAuthorizationCode());
    if(authCode == null) {
      OAuth2NormalizedResponse response = new OAuth2NormalizedResponse();
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      response.setError(ErrorType.INVALID_GRANT.toString());
      response.setErrorDescription("Bad authorization code");
      response.setBodyReturned(true);
      throw new OAuth2Exception(response);
    }
    if(servletRequest.getRedirectURI() != null && !servletRequest.getRedirectURI().equals(authCode.getRedirectURI())) {
      OAuth2NormalizedResponse response = new OAuth2NormalizedResponse();
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      response.setError(ErrorType.INVALID_GRANT.toString());
      response.setErrorDescription("The redirect URI does not match the one used in the authorization request");
      response.setBodyReturned(true);
      throw new OAuth2Exception(response);
    }
  }

}
