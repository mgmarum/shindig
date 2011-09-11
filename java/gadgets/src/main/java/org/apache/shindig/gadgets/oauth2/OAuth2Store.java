/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.oauth.BasicOAuthStore;
import org.apache.shindig.gadgets.oauth2.OAuth2Client.Flow;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persister;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Store extends OAuth2StateChangeListener {
  /**
   * Triggers the persistence layer to preload the {@link OAuth2Client}
   * information and store it in the {@link OAuth2Cache}.
   * 
   * @return true if initialization was successful, false if it was not
   * @throws GadgetException
   */
  public boolean init() throws GadgetException;

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
   * Triggers the target persistence layer to run an import from another source
   * persistence layer.
   * 
   * A common scenario here is to read the contents of the config/oauth2.json
   * file and store it into a DB persistence layer.
   * 
   * @param clean
   *          true will delete all existing information from persistence
   * 
   * @return true if the import succeeded.
   */
  public boolean runImport(OAuth2Persister source, OAuth2Persister target, boolean clean);

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

  public OAuth2Token getToken(Integer index) throws GadgetException;

  public OAuth2Token getToken(String providerName, String gadgetUri, String user, String scope,
      OAuth2Token.Type type) throws GadgetException;

  public void setToken(OAuth2Token token) throws GadgetException;

  public OAuth2Token removeToken(String providerName, String gadgetUri, String user, String scope,
      OAuth2Token.Type type) throws GadgetException;

  public OAuth2Token removeToken(OAuth2Token token) throws GadgetException;

  public OAuth2CallbackState createOAuth2CallbackState(OAuth2Accessor accessor,
      OAuth2Client client, final Flow flow, final SecurityToken securityToken, HttpFetcher fetcher);

  public OAuth2CallbackState getOAuth2CallbackState(Integer stateKey);

  public OAuth2CallbackState removeOAuth2CallbackState(Integer stateKey);

  public OAuth2Token createToken();
}
