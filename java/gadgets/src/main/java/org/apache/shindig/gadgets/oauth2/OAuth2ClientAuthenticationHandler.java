/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.gadgets.http.HttpRequest;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2ClientAuthenticationHandler {
  public String geClientAuthenticationType();

  public void addOAuth2Authentication(HttpRequest request, OAuth2Accessor accessor);
}
