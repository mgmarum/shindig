/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence;

import java.util.Collection;

import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2Context;
import org.apache.shindig.gadgets.oauth2.OAuth2Provider;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Cache {
  Integer getTokenIndex(String providerName, String gadgetUri, String user, OAuth2Token.Type type);

  OAuth2Token getToken(Integer index);

  void storeToken(Integer index, OAuth2Token token) throws OAuth2CacheException;

  OAuth2Token removeToken(Integer index) throws OAuth2CacheException;

  void storeTokens(Collection<OAuth2Token> tokens) throws OAuth2CacheException;

  void clearTokens() throws OAuth2CacheException;

  Integer getProviderIndex(String providerName);

  OAuth2Provider getProvider(Integer index);

  void storeProvider(Integer index, OAuth2Provider provider) throws OAuth2CacheException;

  void storeProviders(Collection<OAuth2Provider> providers) throws OAuth2CacheException;

  OAuth2Provider removeProvider(Integer index) throws OAuth2CacheException;

  void clearProviders() throws OAuth2CacheException;

  Integer getClientIndex(String providerName, String gadgetUri);

  OAuth2Client getClient(Integer index);

  void storeClient(Integer index, OAuth2Client client) throws OAuth2CacheException;

  void storeClients(Collection<OAuth2Client> clients) throws OAuth2CacheException;

  OAuth2Client removeClient(Integer index) throws OAuth2CacheException;

  void clearClients() throws OAuth2CacheException;

  Integer getContextIndex(String gadgetUri, String serviceName, String user);

  Integer getContextIndex(OAuth2Context context);

  OAuth2Context getContext(Integer index);

  void storeContext(Integer index, OAuth2Context context) throws OAuth2CacheException;

  void storeContexts(Collection<OAuth2Context> contexts) throws OAuth2CacheException;

  OAuth2Context removeContext(Integer index) throws OAuth2CacheException;

  void clearContexts() throws OAuth2CacheException;
}
