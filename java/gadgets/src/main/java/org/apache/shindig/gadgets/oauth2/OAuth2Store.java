/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.oauth.BasicOAuthStore;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Store {
  /**
   * Triggers the persistence layer to preload the {@link OAuth2Client}
   * information and store it in the {@link OAuth2Cache}.
   * 
   * May not be supported by all persistence implementations, in that case the
   * return value of this method should be false.
   * 
   * @param oauthConfigStr
   *          optional configuration setting, like a JSON file location
   * @return true if initialization was successful, false if it was not
   * @throws GadgetException
   */
  public boolean initFromConfigString(String oauthConfigStr) throws GadgetException;

  /**
   * Clears all loaded Providers, Clients, Contexts and Tokens from the cache
   * and leaves them intact in the persistence layer.
   * 
   * @return true if the clear succeeded
   * 
   * @throws GadgetException
   */
  public boolean clearCache() throws GadgetException;

  /**
   * Triggers the persistence layer to load values from a source configuration
   * indicated by oauthConfigStr (like oauth2.json) into the persistence layer.
   * 
   * This could be useful for Provider/Client management. Allowing an admin to
   * update oauth2.json and then have it's contents imported into a database
   * persistence implementation.
   * 
   * May not be supported by all persistence implementations, in that case the
   * return value of this method should be false.
   * 
   * @param oauthConfigStr
   *          optional configuration setting, like a JSON file location
   * @return true if the import succeeded
   */
  public boolean importFromConfigString(String oauthConfigStr, boolean clean);

  /**
   * Similar to defaultKey for {@link BasicOAuthStore}
   * 
   * @param client
   */
  public void setDefaultClient(OAuth2Client client);

  /**
   * Similar to callbackUrl for {@link BasicOAuthStore}
   * 
   * @param defaultRedirectUri
   */
  public void setDefaultRedirectUri(String defaultRedirectUri);

  /**
   * Similar to hostProvider for {@link BasicOAuthStore}
   * 
   * @param hostProvider
   */
  public void setHostProvider(com.google.inject.Provider<Authority> hostProvider);

  /**
   * Finds an OAuth2Provider by name.
   * 
   * @param providerName
   *          name of the Provider
   * @return {@OAuth2Provider} with the given name or null if
   *         it cannot be found
   * @throws GadgetException
   */
  public OAuth2Provider getProvider(String providerName) throws GadgetException;

  /**
   * Finds the OAuth2Client for an OAuth2Provider and a gadget
   * 
   * @param providerName
   *          name of the Provider
   * @param gadgetUri
   *          URI of the Gadget
   * @return {@OAuth2Client} for the provider and gadget or null
   *         if it cannot be found
   * @throws GadgetException
   */
  public OAuth2Client getClient(String providerName, String gadgetUri) throws GadgetException;

  /**
   * Finds the OAuth2Context for a provider, gadget and user.
   * 
   * @param providerName
   *          name of the Provider
   * @param gadgetUri
   *          URI of the Gadget
   * @param user
   *          who owns the context
   * @return {@OAuth2Context} for the provider, gadget and user
   *         or null if it cannot be found
   * @throws GadgetException
   */
  public OAuth2Context getContext(String providerName, String gadgetUri, String user)
      throws GadgetException;

  /**
   * Finds the OAuth2Token for a provider, gadget, and token type.
   * 
   * @param providerName
   *          name of the Provider
   * @param gadgetUri
   *          URI of the Gadget
   * @param user
   *          who owns the token
   * @param type
   *          type of token
   * @return {@OAuth2Token} for the provider, gadget, user and
   *         type or null if it cannot be found
   * @throws GadgetException
   */
  public OAuth2Token getToken(String providerName, String gadgetUri, String user,
      OAuth2Token.Type type) throws GadgetException;

  /**
   * Store a OAuth2Token.
   * 
   * @param providerName
   * @param gadgetUri
   * @param user
   * @param type
   * @param token
   * @throws GadgetException
   */
  public void setToken(String providerName, String gadgetUri, String user, OAuth2Token.Type type,
      OAuth2Token token) throws GadgetException;

  /**
   * Remove an OAuth2Token.
   * 
   * @param providerName
   * @param gadgetUri
   * @param user
   * @param type
   * @throws GadgetException
   */
  public void removeToken(String providerName, String gadgetUri, String user, OAuth2Token.Type type)
      throws GadgetException;
}
