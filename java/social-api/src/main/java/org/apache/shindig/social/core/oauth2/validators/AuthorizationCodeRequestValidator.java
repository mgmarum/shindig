package org.apache.shindig.social.core.oauth2.validators;

import org.apache.shindig.social.core.oauth2.OAuth2Client;
import org.apache.shindig.social.core.oauth2.OAuth2DataService;
import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2NormalizedRequest;
import org.apache.shindig.social.core.oauth2.OAuth2NormalizedResponse;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;

import javax.servlet.http.HttpServletResponse;

import com.google.inject.Inject;

public class AuthorizationCodeRequestValidator implements OAuth2RequestValidator {
  
  private OAuth2DataService store = null;

  @Inject
  public AuthorizationCodeRequestValidator(OAuth2DataService store) {
    this.store = store;
  }

  public void validateRequest(OAuth2NormalizedRequest req) throws OAuth2Exception {

    OAuth2Client client = store.getClient(req.getClientId());
    if(client == null) {
      OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
      resp.setError(ErrorType.INVALID_REQUEST.toString());
      resp.setErrorDescription("The client is invalid or not registered");
      resp.setBodyReturned(true);
      resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
      throw new OAuth2Exception(resp);
    }
    String storedURI = client.getRedirectURI();
    if (storedURI == null && req.getRedirectURI() == null) {
      OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
      resp.setError(ErrorType.INVALID_REQUEST.toString());
      resp.setErrorDescription("No redirect_uri registered or received in request");
      resp.setBodyReturned(true);
      resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
      throw new OAuth2Exception(resp);
    }
    if(req.getRedirectURI() != null && storedURI != null){
      if(!req.getRedirectURI().equals(storedURI)){
        OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
        resp.setError(ErrorType.INVALID_REQUEST.toString());
        resp.setErrorDescription("Redirect URI does not match the one registered for this client");
        resp.setBodyReturned(true);
        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
        throw new OAuth2Exception(resp);
      }
    }
  

  }

}
