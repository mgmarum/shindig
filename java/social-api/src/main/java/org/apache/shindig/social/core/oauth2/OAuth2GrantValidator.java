package org.apache.shindig.social.core.oauth2;

/**
 * Handles the validation of a grant requests for access tokens.
 */
public interface OAuth2GrantValidator {
  
  /**
   * Indicates the grant type this handler is registered to handle.
   */
  public String getGrantType();
  
  /**
   * Validates a request for an access token.
   */
  public void validateRequest(OAuth2NormalizedRequest req) throws OAuth2Exception;
}
