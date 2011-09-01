package org.apache.shindig.social.core.oauth2;

/**
 * Represents an exception while dancing with OAuth 2.0.
 */
public class OAuth2Exception extends Exception {

  private static final long serialVersionUID = -5892464438773813010L;
  private OAuth2NormalizedResponse response;

  public OAuth2Exception(OAuth2NormalizedResponse response) {
	  super(response.getErrorDescription());
	  this.response = response;
  }
  
  public OAuth2NormalizedResponse getNormalizedResponse() {
	  return response;
  }
}
