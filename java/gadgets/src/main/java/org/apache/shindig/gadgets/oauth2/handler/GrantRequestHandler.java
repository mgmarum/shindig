/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.handler;

import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface GrantRequestHandler {
  public String getGrantType();

  public boolean isRedirectRequired();

  public boolean isTokenEndpointResponse();

  public boolean isAuthorizationEndpointResponse();

  public HttpRequest getAuthorizationRequest(OAuth2Accessor accessor,
      String completeAuthorizationUrl) throws OAuth2RequestException;

  public String getCompleteUrl(OAuth2Accessor accessor) throws OAuth2RequestException;
}
