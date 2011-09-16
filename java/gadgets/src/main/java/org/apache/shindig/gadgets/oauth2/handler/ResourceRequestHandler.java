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

public interface ResourceRequestHandler {

  public String getTokenType();

  public void addOAuth2Params(final OAuth2Accessor accessor, final HttpRequest request)
      throws OAuth2RequestException;
}