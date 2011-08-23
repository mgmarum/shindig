package org.apache.shindig.social.core.oauth2;

/**
 * Services to support the management of data for the OAuth 2.0 specification.
 * Includes management of clients, authorization codes, access tokens, and
 * refresh tokens.
 * 
 * TODO: client registration services?
 */
public interface OAuth2DataService {

  /**
   * Retrieves a pre-registered client by ID.
   */
  public OAuth2Client getClient(String clientId);
  
  /**
   * Retrieves an authorization code by its value.
   */
  public OAuth2Code getAuthorizationCode(String clientId, String authCode);
  
  /**
   * Registers an authorization code with a client.
   */
  public void registerAuthorizationCode(String clientId, OAuth2Code authCode);
  
  /**
   * Unregisters an authorization code with a client.
   */
  public void unregisterAuthorizationCode(String clientId, String authCode);
  
  /**
   * Retrieves an access token by its value.
   */
  public OAuth2Code getAccessToken(String accessToken);
  
  /**
   * Registers an access token with a client.
   */
  public void registerAccessToken(String clientId, OAuth2Code accessToken);
  
  /**
   * Unregisters an access token with a client.
   */
  public void unregisterAccessToken(String clientId, String accessToken);
  
  /**
   * Retrieves a refresh token by its value.
   */
  public OAuth2Code getRefreshToken(String refreshToken);
  
  /**
   * Registers a refresh token with a client.
   */
  public void registerRefreshToken(String clientId, OAuth2Code refreshToken);
  
  /**
   * Unregisters a refresh token with a client.
   */
  public void unregisterRefreshToken(String clientId, String refreshToken);
}
