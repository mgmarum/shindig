/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.sample;

import java.util.Set;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.GadgetException.Code;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState.State;
import org.apache.shindig.gadgets.oauth2.OAuth2Client.Flow;
import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2Provider;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.OAuth2Token.Type;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2PersistenceException;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persister;

import com.google.inject.Provider;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class BasicOAuth2Store implements OAuth2Store {
  private final OAuth2Cache cache;
  private final OAuth2Persister persister;
  private OAuth2Client defaultClient;
  private String defaultRedirectUri;
  private Provider<Authority> hostProvider;

  public BasicOAuth2Store(final OAuth2Cache cache, final OAuth2Persister persister) {
    this.cache = cache;
    this.persister = persister;
  }

  public boolean init() throws GadgetException {
    this.clearCache();

    try {
      final Set<OAuth2Client> clients = this.persister.loadClients();
      this.cache.storeClients(clients);
    } catch (final OAuth2PersistenceException e) {
      throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 clients", e);
    }

    try {
      final Set<OAuth2Provider> providers = this.persister.loadProviders();
      this.cache.storeProviders(providers);
    } catch (final OAuth2PersistenceException e) {
      throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 providers", e);
    }

    try {
      final Set<OAuth2Token> tokens = this.persister.loadTokens();
      this.cache.storeTokens(tokens);
    } catch (final OAuth2PersistenceException e) {
      throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 tokens", e);
    }
    return true;
  }

  public void setDefaultClient(final OAuth2Client client) {
    this.defaultClient = client;
  }

  public void setDefaultRedirectUri(final String defaultRedirectUri) {
    this.defaultRedirectUri = defaultRedirectUri;
  }

  public void setHostProvider(final Provider<Authority> hostProvider) {
    this.hostProvider = hostProvider;
  }

  public OAuth2Provider getProvider(final String providerName) throws GadgetException {
    final Integer index = this.cache.getProviderIndex(providerName);
    OAuth2Provider provider = this.cache.getProvider(index);
    if (provider == null) {
      try {
        provider = this.persister.findProvider(providerName);
        if (provider != null) {
          this.cache.storeProvider(index, provider);
        }
      } catch (final OAuth2PersistenceException e) {
        throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 provider "
            + providerName, e);
      }
    }

    return provider;
  }

  public OAuth2Client getClient(final String providerName, final String gadgetUri)
      throws GadgetException {
    final Integer index = this.cache.getClientIndex(providerName, gadgetUri);
    OAuth2Client client = this.cache.getClient(index);
    if (client == null) {
      try {
        client = this.persister.findClient(providerName, gadgetUri);
        if (client != null) {
          this.cache.storeClient(index, client);
        }
      } catch (final OAuth2PersistenceException e) {
        throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 client "
            + providerName, e);
      }
    }

    return client;
  }

  public OAuth2Token getToken(final String providerName, final String gadgetUri, final String user,
      final String scope, final OAuth2Token.Type type) throws GadgetException {
    final Integer index = this.cache.getTokenIndex(providerName, gadgetUri, user, scope, type);
    OAuth2Token token = this.cache.getToken(index);
    if (token == null) {
      try {
        token = this.persister.findToken(providerName, gadgetUri, user, scope, type);
        if (token != null) {
          this.cache.storeToken(index, token);
        }
      } catch (final OAuth2PersistenceException e) {
        throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 token "
            + providerName, e);
      }
    }

    return token;
  }

  public void setToken(final String providerName, final String gadgetUri, final String user,
      final String scope, final Type type, final OAuth2Token token) throws GadgetException {
    // TODO Auto-generated method stub
  }

  public void removeToken(final String providerName, final String gadgetUri, final String user,
      final String scope, final Type type) throws GadgetException {
    final Integer index = this.cache.getTokenIndex(providerName, gadgetUri, user, scope, type);
    try {
      final OAuth2Token token = this.cache.removeToken(index);
      if (token != null) {
        this.persister.removeToken(providerName, gadgetUri, user, scope, type);
      }
    } catch (final OAuth2PersistenceException e) {
      throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 token "
          + providerName, e);
    }
  }

  public boolean clearCache() throws GadgetException {
    try {
      this.cache.clearClients();
      this.cache.clearProviders();
      this.cache.clearTokens();
    } catch (final OAuth2PersistenceException e) {
      throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error clearing OAuth2 cache", e);
    }

    return true;
  }

  public boolean runImport(final OAuth2Persister source, final OAuth2Persister target,
      final boolean clean) {
    // TODO ARC
    return false;
  }

  public OAuth2CallbackState createOAuth2CallbackState(final Flow flow, final SecurityToken securityToken, final String realCallbackUrl, final String errorCallbackUrl) {
    final OAuth2CallbackStateImpl ret = new OAuth2CallbackStateImpl(flow, securityToken, realCallbackUrl, errorCallbackUrl);
    final Integer stateKey = ret.getStateKey();
    this.cache.storeOAuth2CallbackState(stateKey, ret);
    return ret;
  }

  public OAuth2CallbackState getOAuth2CallbackState(final Integer stateKey) {
    return this.cache.getOAuth2CallbackState(stateKey);
  }

  public OAuth2CallbackState removeOAuth2CallbackState(final Integer stateKey) {
    final OAuth2CallbackState ret = this.cache.removeOAuth2CallbackState(stateKey);
    if (ret != null) {
      ((OAuth2CallbackStateImpl) ret).invalidate();
    }

    return ret;
  }

  public void stateChange(final OAuth2CallbackState state, final State fromState,
      final State toState) {
    if (state != null) {
      if ((toState == OAuth2CallbackState.State.ACCESS_FAILED)
          || (toState == OAuth2CallbackState.State.AUTHORIZATION_FAILED)
          || (toState == OAuth2CallbackState.State.REFERESH_FAILED)) {
        this.removeOAuth2CallbackState(state.getStateKey());
      }
    }
  }
}
