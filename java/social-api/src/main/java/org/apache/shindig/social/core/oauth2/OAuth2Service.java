package org.apache.shindig.social.core.oauth2;



/**
 * Services to support OAuth 2.0 flows.
 */
public interface OAuth2Service {
  
  // --------------------------- VALIDATION SERVICES --------------------------
  /**
   * Validates a client.
   */
  public void authenticateClient(OAuth2NormalizedRequest req) throws OAuth2Exception;
  
  /**
   * Validates a client's request for an authorization token.
   */
  public void validateRequestForAuthCode(OAuth2NormalizedRequest req) throws OAuth2Exception;
  
  public OAuth2Code retrieveAuthCode(String clientId, String authCode) throws OAuth2Exception;
  
  /**
   * Used to validates a grant for an access token.
   */
  public AuthorizationGrantHandler getAuthorizationGrantHandler(String grantType) throws OAuth2Exception;
  
  /**
   * Retrieves an access token.
   */
  public OAuth2Token retrieveAccessToken(String accessToken) throws OAuth2Exception;
  
  /**
   * Validates a client's request to use access a resource.
   */
  public void validateRequestForResource(OAuth2NormalizedRequest req) throws OAuth2Exception;
  
  // ------------------------ TOKEN GENERATION SERVICES -----------------------
  /**
   * Generates an authorization code from a client OAuth 2.0 request.
   */
  public OAuth2Code generateAuthorizationCode(OAuth2NormalizedRequest req);
  
  /**
   * Generates an access token from a client OAuth 2.0 request.
   */
  public OAuth2Token generateAccessToken(OAuth2NormalizedRequest req);
  
  /**
   * Generates a refresh token from a client OAuth 2.0 request.
   */
  public OAuth2Token generateRefreshToken(OAuth2NormalizedRequest req);
  
  // ------------------- CLIENT TOKEN MANAGEMENT SERVICES ---------------------
  /**
   * Retrieves a pre-registered client by ID.
   */
  public OAuth2Client getClientById(String clientId);
  
  /**
   * Registers an authorization code with a client.
   */
  public void registerAuthorizationCode(String clientId, OAuth2Code authCode);
  
  /**
   * Unregisters an authorization code with a client.
   */
  public void unregisterAuthorizationCode(String clientId, String authCode);
  
  /**
   * Registers an access token with a client.
   */
  public void registerAccessToken(String clientId, OAuth2Token accessToken);
  
  /**
   * Unregisters an access token with a client.
   */
  public void unregisterAccessToken(String clientId, String accessToken);
  
  /**
   * Registers a refresh token with a client.
   */
  public void registerRefreshToken(String clientId, OAuth2Code refreshToken);
  
  /**
   * Unregisters a refresh token with a client.
   */
  public void unregisterRefreshToken(String clientId, String refreshToken);
}
