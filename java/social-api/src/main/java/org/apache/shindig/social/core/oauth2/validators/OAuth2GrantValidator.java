package org.apache.shindig.social.core.oauth2.validators;


/**
 * Handles the validation of a grant requests for access tokens.
 */
public interface OAuth2GrantValidator extends OAuth2RequestValidator{
  
  /**
   * Indicates the grant type this handler is registered to handle.
   */
  public String getGrantType();
}
