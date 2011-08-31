package org.apache.shindig.social.core.oauth2.validators;

import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2NormalizedRequest;

public interface OAuth2RequestValidator {
  
  public void validateRequest(OAuth2NormalizedRequest req) throws OAuth2Exception;

}
