package org.apache.shindig.social.core.oauth2.validators;

import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.social.core.oauth2.OAuth2Code;
import org.apache.shindig.social.core.oauth2.OAuth2DataService;
import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2NormalizedRequest;
import org.apache.shindig.social.core.oauth2.OAuth2NormalizedResponse;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;

import com.google.inject.Inject;

public class DefaultResourceRequestValidator implements OAuth2ProtectedResourceValidator {

  
  private OAuth2DataService store = null;

  @Inject
  public DefaultResourceRequestValidator(OAuth2DataService store) {
    this.store = store;
  }

  public void validateRequest(OAuth2NormalizedRequest req) throws OAuth2Exception {
    validateRequestForResource(req, null);

  }

  /**
   * TODO: implement scope handling.
   */
  public void validateRequestForResource(OAuth2NormalizedRequest req, Object resourceRequest)
      throws OAuth2Exception {

    OAuth2Code token = store.getAccessToken(req.getAccessToken());
    if (token == null) throwAccessDenied("Access token is invalid.");
    if (token.getExpiration() > -1 && token.getExpiration() < System.currentTimeMillis()) {
      throwAccessDenied("Access token has expired.");
    }
    if (resourceRequest != null) {
      // TODO: validate that requested resource is within scope
    }
      

  }
  
  private void throwAccessDenied(String msg) throws OAuth2Exception {
    OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
    resp.setError(ErrorType.ACCESS_DENIED.toString());
    resp.setErrorDescription(msg);
    resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
    throw new OAuth2Exception(resp);
  }
  
}
