/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

/**
 * Error strings to be returned to gadgets as "oauthError" data.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public enum OAuth2Error {
  UNKNOWN_PROBLEM("%s"),

  BAD_OAUTH_CONFIGURATION("%s"),

  MISSING_SERVER_RESPONSE("No response from server"),

  BAD_OAUTH_TOKEN_URL("No %s URL specified"),

  MISSING_OAUTH_PARAMETER("No %s returned from service provider"),

  UNAUTHENTICATED("Unauthenticated OAuth fetch"),

  INVALID_REQUEST("%s"),

  UNAUTHORIZED_CLIENT("%s"),

  ACCESS_DENIED("Access denied by user"),

  UNSUPPORTED_RESPONSE_TYPE("%s"),

  INVALID_SCOPE("%s"),

  SERVER_ERROR("%s"),

  NO_STATE("Authorization Server did not return a state"),

  INVALID_STATE("A valid state for the OAuth2 Authorization response could not be found"),

  INVALID_STATE_CHANGE("Invalid OAuth2 State change requested by OAuth2CallbackServlet"),

  INVALID_CLIENT("Invalid OAuth2 State change requested by OAuth2CallbackServlet"),

  INVALID_GRANT("The provided authorization grant is invalid"),

  UNSUPPORTED_GRANT_TYPE("The authorization grant type is not supported"),

  TEMPORARILY_UNAVAILABLE("%s");

  private final String formatString;

  OAuth2Error(final String formatString) {
    this.formatString = formatString;
  }

  @Override
  public String toString() {
    return this.formatString;
  }
}
