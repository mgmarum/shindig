package org.apache.shindig.gadgets.oauth2.persistence.sample;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2Provider;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2CacheException;

import com.google.inject.Inject;
import com.google.inject.Singleton;

@Singleton
public class OAuth2CacheImpl implements OAuth2Cache {
  private final static String OAUTH2_PREFIX = "OAUTH2_";

  private final static String OAUTH2_TOKEN_PREFIX = OAuth2CacheImpl.OAUTH2_PREFIX + "TOKEN_";
  private final static String OAUTH2_PROVIDER_PREFIX = OAuth2CacheImpl.OAUTH2_PREFIX + "PROVIDER_";
  private final static String OAUTH2_CLIENT_PREFIX = OAuth2CacheImpl.OAUTH2_PREFIX + "CLIENT_";
  private final static String OAUTH2_CONTEXT_PREFIX = OAuth2CacheImpl.OAUTH2_PREFIX + "CONTEXT_";

  private final Map<Integer, OAuth2Token> tokens;
  private final Map<Integer, OAuth2Provider> providers;
  private final Map<Integer, OAuth2Client> clients;
  private final Map<Integer, OAuth2CallbackState> states;

  @Inject
  OAuth2CacheImpl() {
    this.tokens = Collections.synchronizedMap(new HashMap<Integer, OAuth2Token>());
    this.providers = Collections.synchronizedMap(new HashMap<Integer, OAuth2Provider>());
    this.clients = Collections.synchronizedMap(new HashMap<Integer, OAuth2Client>());
    this.states = Collections.synchronizedMap(new HashMap<Integer, OAuth2CallbackState>());
  }

  public Integer getTokenIndex(final String providerName, final String gadgetUri,
      final String user, final String scope, final OAuth2Token.Type type) {
    return Integer.valueOf((OAuth2CacheImpl.OAUTH2_TOKEN_PREFIX + ":" + gadgetUri + ":"
        + providerName + ":" + user + ":" + scope + ":" + type.name()).hashCode());
  }

  public OAuth2Token getToken(final Integer index) {
    return this.tokens.get(index);
  }

  public void storeToken(final Integer index, final OAuth2Token token) throws OAuth2CacheException {
    this.tokens.put(index, token);
  }

  public void storeTokens(final Collection<OAuth2Token> tokens) throws OAuth2CacheException {
    for (final OAuth2Token token : tokens) {
      this.tokens.put(
          this.getTokenIndex(token.getProviderName(), token.getGadgetUri(), token.getUser(),
              token.getScope(), token.getType()), token);
    }
  }

  public OAuth2Token removeToken(final Integer index) throws OAuth2CacheException {
    return this.tokens.remove(index);
  }

  public void clearTokens() throws OAuth2CacheException {
    this.tokens.clear();
  }

  public Integer getProviderIndex(final String serviceName) {
    return Integer.valueOf((OAuth2CacheImpl.OAUTH2_PROVIDER_PREFIX + ":" + serviceName).hashCode());
  }

  public OAuth2Provider getProvider(final Integer index) {
    return this.providers.get(index);
  }

  public void storeProvider(final Integer index, final OAuth2Provider provider)
      throws OAuth2CacheException {
    this.providers.put(index, provider);
  }

  public void storeProviders(final Collection<OAuth2Provider> providers)
      throws OAuth2CacheException {
    for (final OAuth2Provider provider : providers) {
      final Integer index = this.getProviderIndex(provider.getName());
      this.providers.put(index, provider);
    }
  }

  public OAuth2Provider removeProvider(final Integer index) throws OAuth2CacheException {
    return this.providers.remove(index);
  }

  public void clearProviders() throws OAuth2CacheException {
    this.providers.clear();
  }

  public Integer getClientIndex(final String providerName, final String gadgetUri) {
    return Integer
        .valueOf((OAuth2CacheImpl.OAUTH2_CLIENT_PREFIX + ":" + providerName + ":" + gadgetUri)
            .hashCode());
  }

  public OAuth2Client getClient(final Integer index) {
    final OAuth2Client ret = this.clients.get(index);
    return ret;
  }

  public void storeClient(final Integer index, final OAuth2Client client)
      throws OAuth2CacheException {
    this.clients.put(index, client);
  }

  public void storeClients(final Collection<OAuth2Client> clients) throws OAuth2CacheException {
    for (final OAuth2Client client : clients) {
      this.clients
          .put(this.getClientIndex(client.getProviderName(), client.getGadgetUri()), client);
    }
  }

  public OAuth2Client removeClient(final Integer index) throws OAuth2CacheException {
    return this.clients.remove(index);
  }

  public void clearClients() throws OAuth2CacheException {
    this.clients.clear();
  }

  public void storeOAuth2CallbackState(Integer stateKey, OAuth2CallbackState state) {
    this.states.put(stateKey, state);
  }

  public OAuth2CallbackState getOAuth2CallbackState(Integer stateKey) {
    return this.states.get(stateKey);
  }

  public OAuth2CallbackState removeOAuth2CallbackState(Integer stateKey) {
    return this.states.remove(stateKey);
  }
}
