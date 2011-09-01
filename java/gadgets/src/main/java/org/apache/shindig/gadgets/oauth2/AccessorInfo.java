/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.gadgets.oauth2.core.Consumer;
import org.apache.shindig.gadgets.oauth2.core.OAuth2Accessor;

/**
 * OAuth2 related data accessor
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class AccessorInfo {

  public static enum HttpMethod {
    GET, POST
  }

  public static enum OAuth2ParamLocation {
    AUTH_HEADER, POST_BODY, URI_QUERY
  }

  private final OAuth2Accessor accessor;
  private final Consumer consumer;
  private final HttpMethod httpMethod;
  private final OAuth2ParamLocation paramLocation;
  private String sessionHandle;
  private long tokenExpireMillis;

  public AccessorInfo(final OAuth2Accessor accessor, final Consumer consumer,
      final HttpMethod httpMethod, final OAuth2ParamLocation paramLocation,
      final String sessionHandle, final long tokenExpireMillis) {
    this.accessor = accessor;
    this.consumer = consumer;
    this.httpMethod = httpMethod;
    this.paramLocation = paramLocation;
    this.sessionHandle = sessionHandle;
    this.tokenExpireMillis = tokenExpireMillis;
  }

  public OAuth2ParamLocation getParamLocation() {
    return this.paramLocation;
  }

  public OAuth2Accessor getAccessor() {
    return this.accessor;
  }

  public Consumer getConsumer() {
    return this.consumer;
  }

  public HttpMethod getHttpMethod() {
    return this.httpMethod;
  }

  public String getSessionHandle() {
    return this.sessionHandle;
  }

  public void setSessionHandle(final String sessionHandle) {
    this.sessionHandle = sessionHandle;
  }

  public long getTokenExpireMillis() {
    return this.tokenExpireMillis;
  }

  public void setTokenExpireMillis(final long tokenExpireMillis) {
    this.tokenExpireMillis = tokenExpireMillis;
  }
}
