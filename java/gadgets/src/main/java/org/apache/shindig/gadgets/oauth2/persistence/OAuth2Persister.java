/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence;

import java.util.Set;

import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2Context;
import org.apache.shindig.gadgets.oauth2.OAuth2Provider;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Persister {
  Set<OAuth2Client> loadClients(String oauthConfigStr) throws OAuth2PersistenceException;

  Set<OAuth2Context> loadContexts(String oauthConfigStr) throws OAuth2PersistenceException;

  Set<OAuth2Provider> loadProviders(String oauthConfigStr) throws OAuth2PersistenceException;

  Set<OAuth2Token> loadTokens(String oauthConfigStr) throws OAuth2PersistenceException;

  OAuth2Provider findProvider(String providerName) throws OAuth2PersistenceException;

  OAuth2Client findClient(String providerName, String gadgetUri) throws OAuth2PersistenceException;

  OAuth2Context findContext(String providerName, String gadgetUri, String user)
      throws OAuth2PersistenceException;

  OAuth2Token findToken(String providerName, String gadgetUri, String user, OAuth2Token.Type type)
      throws OAuth2PersistenceException;

  boolean removeToken(String providerName, String gadgetUri, String user, OAuth2Token.Type type);
}
