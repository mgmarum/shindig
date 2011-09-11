/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence;

import java.util.Collection;

import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2Provider;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Cache {
  void clearClients() throws OAuth2CacheException;

  void clearProviders() throws OAuth2CacheException;

  void clearTokens() throws OAuth2CacheException;

  OAuth2Client getClient(Integer index);

  Integer getClientIndex(String providerName, String gadgetUri);

  OAuth2Provider getProvider(Integer index);

  Integer getProviderIndex(String providerName);

  OAuth2Token getToken(Integer index);

  Integer getTokenIndex(OAuth2Token token);

  Integer getTokenIndex(String providerName, String gadgetUri, String user, String scope,
      OAuth2Token.Type type);

  OAuth2Client removeClient(Integer index) throws OAuth2CacheException;

  OAuth2Provider removeProvider(Integer index) throws OAuth2CacheException;

  OAuth2Token removeToken(Integer index) throws OAuth2CacheException;

  void storeClient(Integer index, OAuth2Client client) throws OAuth2CacheException;

  void storeClients(Collection<OAuth2Client> clients) throws OAuth2CacheException;

  void storeProvider(Integer index, OAuth2Provider provider) throws OAuth2CacheException;

  void storeProviders(Collection<OAuth2Provider> providers) throws OAuth2CacheException;

  void storeToken(Integer index, OAuth2Token token) throws OAuth2CacheException;

  void storeTokens(Collection<OAuth2Token> tokens) throws OAuth2CacheException;

  void storeOAuth2CallbackState(Integer stateKey, OAuth2CallbackState state);

  OAuth2CallbackState getOAuth2CallbackState(Integer stateKey);

  OAuth2CallbackState removeOAuth2CallbackState(Integer stateKey);
}
