/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2.ClientAuthMethod;
import org.apache.shindig.gadgets.oauth2.OAuth2Exception;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Accessor {
  public String getAuthorizationUrl();

  public OAuth2Message getAccessTokenMessage(ClientAuthMethod method) throws OAuth2Exception;

  public OAuth2Message getAccessToken(OAuth2Message request) throws OAuth2Exception;

  public void validate(OAuth2Message message) throws OAuth2Exception;

  public HttpResponse access(HttpUriRequest request) throws OAuth2Exception;

  public String getAuthorizationHeader(HttpUriRequest request) throws OAuth2Exception;

  public void setRequestToken(String requestToken);

  public void setAccessToken(String accessToken);

  public void setTokenSecret(String tokenSecret);
}
