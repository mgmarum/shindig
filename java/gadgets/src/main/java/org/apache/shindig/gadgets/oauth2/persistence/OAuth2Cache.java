/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence;

import java.util.Collection;

import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Cache {
  void clearClients() throws OAuth2CacheException;

  void clearTokens() throws OAuth2CacheException;

  OAuth2Client getClient(Integer index);

  Integer getClientIndex(String gadgetUri, String serviceName);

  OAuth2Accessor getOAuth2Accessor(Integer index);

  Integer getOAuth2AccessorIndex(String gadgetUri, String serviceName, String user, String scope);

  OAuth2Token getToken(Integer index);

  Integer getTokenIndex(OAuth2Token token);

  Integer getTokenIndex(String gadgetUri, String serviceName, String user, String scope,
      OAuth2Token.Type type);

  OAuth2Client removeClient(Integer index) throws OAuth2CacheException;

  OAuth2Accessor removeOAuth2Accessor(OAuth2Accessor accessor);

  OAuth2Token removeToken(Integer index) throws OAuth2CacheException;

  void storeClient(Integer index, OAuth2Client client) throws OAuth2CacheException;

  void storeClients(Collection<OAuth2Client> clients) throws OAuth2CacheException;

  void storeOAuth2Accessor(OAuth2Accessor accessor);

  void storeToken(Integer index, OAuth2Token token) throws OAuth2CacheException;

  void storeTokens(Collection<OAuth2Token> tokens) throws OAuth2CacheException;
}
