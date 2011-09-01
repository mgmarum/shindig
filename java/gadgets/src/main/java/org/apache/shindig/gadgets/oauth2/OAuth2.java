/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import java.util.Arrays;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2 {
  public static final String ENCODE = "UTF-8";
  public static final String CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded";
  public static final String HEADER_AUTHORIZATION = "Authorization";

  public static final String PARAM_RESPONSE_TYPE = "response_type";
  public static final String PARAM_SCOPE = "scope";
  public static final String PARAM_REDIRECT_URI = "redirect_uri";
  public static final String PARAM_STATE = "state";
  public static final String PARAM_CODE = "code";
  public static final String PARAM_ACCESS_TOKEN = "access_token";
  public static final String PARAM_TOKEN_TYPE = "token_type";
  public static final String PARAM_EXPIRES_IN = "expires_in";
  public static final String PARAM_ERROR = "error";
  public static final String PARAM_ERROR_DESCRIPTION = "error_description";
  public static final String PARAM_ERROR_URI = "error_uri";
  public static final String PARAM_GRANT_TYPE = "grant_type";
  public static final String PARAM_CLIENT_ID = "client_id";
  public static final String PARAM_CLIENT_SECRET = "client_secret";
  public static final String PARAM_USERNAME = "username";
  public static final String PARAM_PASSWORD = "password";
  public static final String PARAM_REFRESH_TOKEN = "refresh_token";

  // defined value for response_type
  public static enum ResponseType {
    token, code;
  };

  // defined value for grant type
  public static enum GrantType {
    authorization_code, refresh_token, password, client_credential
  };

  // defined value for error
  public static enum Error {
    invalid_request, unauthorized_client, access_denied, unsupported_response_type, invalid_scope, server_error, temporarily_unavailable, unsupported_grant_type
  };

  public static enum ClientAuthMethod {
    auth_header, parameter
  };

  /**
   * public static final String ERROR_INVALID_REQUEST = "invalid_request";
   * public static final String ERROR_UNAUTHORIZED_CLIENT =
   * "unauthorized_client"; public static final String ERROR_ACCESS_DENIED =
   * "access_denied"; public static final String ERROR_UNSUPPORTED_RESPONSE_TYPE
   * = "unsupported_response_type"; public static final String
   * ERROR_INVALID_SCOPE = "invalid_scope"; public static final String
   * ERROR_SERVER_ERROR = "server_error"; public static final String
   * ERROR_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"; public static
   * final String ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
   **/

  // authorization request/response
  public static final String AUTHORIZATION_REQUEST = "authorization_request";
  public static final String AUTHORIZATION_RESPONSE = "authorization_response";
  // access token request/response
  public static final String ACCESS_TOKEN_REQUEST = "access_token_request";
  public static final String ACCESS_TOKEN_RESPONSE = "access_token_response";
  // refresh token request/response
  public static final String REFRESH_TOKEN_REQUEST = "refresh_token_request";
  public static final String REFRESH_TOKEN_RESPONSE = "refresh_token_response";

  static {
    Arrays.asList(OAuth2.PARAM_RESPONSE_TYPE, OAuth2.PARAM_CLIENT_ID, OAuth2.PARAM_REDIRECT_URI,
        OAuth2.PARAM_STATE, OAuth2.PARAM_SCOPE);
    Arrays.asList(OAuth2.PARAM_CODE, OAuth2.PARAM_STATE);
    Arrays.asList(OAuth2.PARAM_GRANT_TYPE, OAuth2.PARAM_CODE, OAuth2.PARAM_REDIRECT_URI);
    Arrays.asList(OAuth2.PARAM_GRANT_TYPE);
  }

  public static final int PROFILE_AUTHORIZATION_CODE = 0x0001;
  public static final int PROFILE_IMPLICIT = 0x0002;
  public static final int PROFILE_RESOURCE_OWNER_CREDENTIALS = 0x0004;
  public static final int PROFILE_CLIENT_CREDENTIALS = 0x0008;

  public static String getProfileName(final int profile) {
    switch (profile) {
    case PROFILE_AUTHORIZATION_CODE:
      return "Authorization Code";
    case PROFILE_IMPLICIT:
      return "Implicit";
    case PROFILE_RESOURCE_OWNER_CREDENTIALS:
      return "Resource Owner Password Credentials";
    case PROFILE_CLIENT_CREDENTIALS:
      return "Client Credentials";
    default:
      return "Unknown";
    }
  }

  public static ResponseType getResponseType(final int profile) {
    switch (profile) {
    case PROFILE_AUTHORIZATION_CODE:
      return ResponseType.code;
    case PROFILE_IMPLICIT:
      return ResponseType.token;
    default:
      return null;
    }
  }

  public static GrantType getGrantType(final int profile) {
    switch (profile) {
    case PROFILE_AUTHORIZATION_CODE:
      return GrantType.authorization_code;
    case PROFILE_RESOURCE_OWNER_CREDENTIALS:
      return GrantType.password;
    case PROFILE_CLIENT_CREDENTIALS:
      return GrantType.client_credential;
    default:
      return null;
    }
  }
}
