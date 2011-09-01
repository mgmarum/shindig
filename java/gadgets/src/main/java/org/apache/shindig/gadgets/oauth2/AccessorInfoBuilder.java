/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */

package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.gadgets.oauth2.AccessorInfo.HttpMethod;
import org.apache.shindig.gadgets.oauth2.AccessorInfo.OAuth2ParamLocation;
import org.apache.shindig.gadgets.oauth2.core.Consumer;
import org.apache.shindig.gadgets.oauth2.core.OAuth2Accessor;

/**
 * Builder for AccessorInfo object.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION

public class AccessorInfoBuilder {

  private Consumer consumer;
  private String requestToken;
  private String accessToken;
  private String tokenSecret;
  private String sessionHandle;
  private long tokenExpireMillis;
  private OAuth2ParamLocation location;
  private HttpMethod method;

  public AccessorInfoBuilder() {
  }

  public AccessorInfo create(final OAuth2ResponseParams responseParams)
      throws OAuth2RequestException {
    if (this.location == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "no location");
    }
    if (this.consumer == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "no consumer");
    }

    final OAuth2Accessor accessor = null; // TODO new
                                          // OAuth2Accessor(consumer.getConsumer());

    // request token/access token/token secret can all be null, for signed
    // fetch, or if the OAuth
    // dance is just beginning
    accessor.setRequestToken(this.requestToken);
    accessor.setAccessToken(this.accessToken);
    accessor.setTokenSecret(this.tokenSecret);
    return new AccessorInfo(accessor, this.consumer, this.method, this.location,
        this.sessionHandle, this.tokenExpireMillis);
  }

  public void setConsumer(final Consumer consumer) {
    this.consumer = consumer;
  }

  public void setRequestToken(final String requestToken) {
    this.requestToken = requestToken;
  }

  public void setAccessToken(final String accessToken) {
    this.accessToken = accessToken;
  }

  public void setTokenSecret(final String tokenSecret) {
    this.tokenSecret = tokenSecret;
  }

  public void setParameterLocation(final OAuth2ParamLocation location) {
    this.location = location;
  }

  public void setMethod(final HttpMethod method) {
    this.method = method;
  }

  public void setSessionHandle(final String sessionHandle) {
    this.sessionHandle = sessionHandle;
  }

  public void setTokenExpireMillis(final long tokenExpireMillis) {
    this.tokenExpireMillis = tokenExpireMillis;
  }
}
