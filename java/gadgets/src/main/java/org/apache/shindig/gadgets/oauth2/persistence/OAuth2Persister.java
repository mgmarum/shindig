/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence;

import java.util.Set;

import org.apache.shindig.gadgets.oauth2.OAuth2Token;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Persister {
  OAuth2Token createToken();

  OAuth2Client findClient(String gadgetUri, String serviceName) throws OAuth2PersistenceException;

  OAuth2Token findToken(String gadgetUri, String serviceName, String user, String scope,
      OAuth2Token.Type type) throws OAuth2PersistenceException;

  void insertToken(OAuth2Token token) throws OAuth2PersistenceException;

  Set<OAuth2Client> loadClients() throws OAuth2PersistenceException;

  Set<OAuth2Token> loadTokens() throws OAuth2PersistenceException;

  boolean removeToken(String gadgetUri, String serviceName, String user, String scope,
      OAuth2Token.Type type) throws OAuth2PersistenceException;

  void updateToken(OAuth2Token token) throws OAuth2PersistenceException;
}
