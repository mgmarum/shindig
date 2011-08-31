package org.apache.shindig.social.core.oauth2.validators;

import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2NormalizedRequest;

public interface OAuth2ProtectedResourceValidator extends OAuth2RequestValidator {
  
  public void validateRequestForResource(OAuth2NormalizedRequest req, Object resourceRequest) throws OAuth2Exception;

}
