package org.apache.shindig.gadgets.oauth2;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

public interface OAuth2Message {
  public final static String ACCESS_DENIED = "access_denied";
  public final static String ACCESS_TOKEN = "access_token";
  public final static String AUTHORIZATION = "code";
  public final static String AUTHORIZATION_CODE = "authorization_code";
  public final static String BASIC_AUTH_TYPE = "Basic";
  public final static String BEARER_TOKEN_TYPE = "Bearer";
  public final static String CLIENT_CREDENTIALS = "client_credentials";
  public final static String CLIENT_ID = "client_id";
  public final static String CLIENT_SECRET = "client_secret";
  public final static String CONFIDENTIAL_CLIENT_TYPE = "confidential";
  public final static String ERROR = "error";
  public final static String ERROR_DESCRIPTION = "error_description";
  public final static String ERROR_URI = "error_uri";
  public final static String EXPIRES_IN = "expires_in";
  public final static String GRANT_TYPE = "grant_type";
  public final static String INVALID_CLIENT = "invalid_client";
  public final static String INVALID_GRANT = "invalid_client";
  public final static String INVALID_REQUEST = "invalid_request";
  public final static String INVALID_SCOPE = "invalid_scope";
  public final static String NO_GRANT_TYPE = "NONE";
  public final static String PUBLIC_CLIENT_TYPE = "public";
  public final static String REDIRECT_URI = "redirect_uri";
  public final static String REFRESH_TOKEN = "refresh_token";
  public final static String RESPONSE_TYPE = "response_type";
  public final static String SCOPE = "scope";
  public final static String SERVER_ERROR = "server_error";
  public final static String STATE = "state";
  public final static String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
  public final static String TOKEN_TYPE = "token_type";
  public final static String TOKEN_RESPONSE = "token";
  public final static String UNAUTHORIZED_CLIENT = "authorized_client";
  public final static String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
  public final static String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";

  public String getAccessToken();

  public String getAuthorization();

  public OAuth2Error getError();

  public String getErrorDescription();

  public String getErrorUri();

  public String getExpiresIn();

  public Map<String, String> getParameters();

  public String getRefreshToken();

  public String getState();

  public String getTokenType();

  public void parseFragment(String fragment);

  public void parseJSON(String jsonString);

  public void parseQuery(String queryString);

  public void parseRequest(HttpServletRequest request);
}
