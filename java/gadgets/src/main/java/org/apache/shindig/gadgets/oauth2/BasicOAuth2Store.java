/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shindig.gadgets.oauth2;

import java.util.Set;

import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.GadgetException.Code;
import org.apache.shindig.gadgets.oauth2.OAuth2Token.Type;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2CacheException;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Encrypter;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2PersistenceException;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persister;

import com.google.inject.Inject;

/**
 * see {@link OAuth2Store}
 * 
 * Default OAuth2Store.
 * 
 * Uses 3 Guice bindings to achieve storage implementation.
 * 
 * 1) {@link OAuth2Persister} 2) {@link OAuth2Cache} 3) {@link OAuth2Encrypter}
 * 
 */
public class BasicOAuth2Store implements OAuth2Store {
  private final OAuth2Cache cache;
  private final OAuth2Persister persister;
  private final String globalRedirectUri;

  @Inject
  public BasicOAuth2Store(final OAuth2Cache cache, final OAuth2Persister persister,
      final String globalRedirectUri) {
    this.cache = cache;
    this.persister = persister;
    this.globalRedirectUri = globalRedirectUri;
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
      final Set<OAuth2Token> tokens = this.persister.loadTokens();
      this.cache.storeTokens(tokens);
    } catch (final OAuth2PersistenceException e) {
      throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 tokens", e);
    }
    return true;
  }

  public OAuth2Token getToken(final String gadgetUri, final String serviceName, final String user,
      final String scope, final OAuth2Token.Type type) throws GadgetException {
    final Integer index = this.cache.getTokenIndex(gadgetUri, serviceName, user, scope, type);
    OAuth2Token token = this.cache.getToken(index);
    if (token == null) {
      try {
        token = this.persister.findToken(gadgetUri, serviceName, user, scope, type);
        if (token != null) {
          this.cache.storeToken(index, token);
        }
      } catch (final OAuth2PersistenceException e) {
        throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 token " + index,
            e);
      }
    }

    return token;
  }

  public void setToken(final OAuth2Token token) throws GadgetException {
    if (token != null) {
      final Integer index = this.cache.getTokenIndex(token);
      final OAuth2Token existingToken = this.getToken(token.getGadgetUri(), token.getServiceName(),
          token.getUser(), token.getScope(), token.getType());
      try {
        if (existingToken == null) {
          this.persister.insertToken(token);
        } else {
          this.cache.removeToken(index);
          this.persister.updateToken(token);
        }
        this.cache.storeToken(index, token);
      } catch (final OAuth2CacheException e) {
        throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error storing OAuth2 token " + index,
            e);
      } catch (final OAuth2PersistenceException e) {
        throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error storing OAuth2 token " + index,
            e);
      }
    }
  }

  public OAuth2Token removeToken(final OAuth2Token token) throws GadgetException {
    if (token != null) {
      return this.removeToken(token.getServiceName(), token.getGadgetUri(), token.getUser(),
          token.getScope(), token.getType());
    }
    return null;
  }

  public OAuth2Token removeToken(final String gadgetUri, final String serviceName,
      final String user, final String scope, final Type type) throws GadgetException {
    final Integer index = this.cache.getTokenIndex(gadgetUri, serviceName, user, scope, type);
    try {
      final OAuth2Token token = this.cache.removeToken(index);
      if (token != null) {
        this.persister.removeToken(gadgetUri, serviceName, user, scope, type);
      }

      return token;
    } catch (final OAuth2PersistenceException e) {
      throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 token "
          + serviceName, e);
    }
  }

  public boolean clearCache() throws GadgetException {
    try {
      this.cache.clearClients();
      this.cache.clearTokens();
    } catch (final OAuth2PersistenceException e) {
      throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error clearing OAuth2 cache", e);
    }

    return true;
  }

  public boolean runImport(final OAuth2Persister source, final OAuth2Persister target,
      final boolean clean) {
    // No import for default persistence
    return false;
  }

  public OAuth2Token createToken() {
    return this.persister.createToken();
  }

  public OAuth2Accessor getOAuth2Accessor(final Integer index) {
    return this.cache.getOAuth2Accessor(index);
  }

  public OAuth2Accessor getOAuth2Accessor(final String gadgetUri, final String serviceName,
      final String user, final String scope) throws GadgetException {
    final Integer index = this.cache.getOAuth2AccessorIndex(gadgetUri, serviceName, user, scope);

    OAuth2Accessor ret = this.cache.getOAuth2Accessor(index);

    if (ret == null) {
      final OAuth2Client client = this.getClient(gadgetUri, serviceName);

      if (client != null) {
        final OAuth2Token accessToken = this.getToken(gadgetUri, serviceName, user, scope,
            OAuth2Token.Type.ACCESS);
        final OAuth2Token refreshToken = this.getToken(gadgetUri, serviceName, user, scope,
            OAuth2Token.Type.REFRESH);

        final BasicOAuth2Accessor newAccessor = new BasicOAuth2Accessor(gadgetUri, serviceName,
            user, scope, client.isAllowModuleOverride(), this, this.globalRedirectUri);
        newAccessor.setAccessToken(accessToken);
        newAccessor.setAuthorizationUrl(client.getAuthorizationUrl());
        newAccessor.setClientAuthenticationType(client.getClientAuthenticationType());
        newAccessor.setClientId(client.getClientId());
        newAccessor.setClientSecret(client.getClientSecret());
        newAccessor.setGrantType(client.getGrantType());
        newAccessor.setRedirectUri(client.getRedirectUri());
        newAccessor.setRefreshToken(refreshToken);
        newAccessor.setTokenUrl(client.getTokenUrl());
        newAccessor.setType(client.getType());
        ret = newAccessor;

        this.storeOAuth2Accessor(ret);
      }
    }

    return ret;
  }

  public OAuth2Client getClient(final String gadgetUri, final String serviceName)
      throws GadgetException {
    final Integer index = this.cache.getClientIndex(gadgetUri, serviceName);
    OAuth2Client client = this.cache.getClient(index);
    if (client == null) {
      try {
        client = this.persister.findClient(gadgetUri, serviceName);
        if (client != null) {
          this.cache.storeClient(index, client);
        }
      } catch (final OAuth2PersistenceException e) {
        throw new GadgetException(Code.OAUTH_STORAGE_ERROR, "Error loading OAuth2 client "
            + serviceName, e);
      }
    }

    return client;
  }

  public Integer getOAuth2AccessorIndex(final String gadgetUri, final String serviceName,
      final String user, final String scope) {
    return this.cache.getOAuth2AccessorIndex(gadgetUri, serviceName, user, scope);
  }

  public OAuth2Accessor removeOAuth2Accessor(final OAuth2Accessor accessor) {
    return this.cache.removeOAuth2Accessor(accessor);
  }

  public void storeOAuth2Accessor(final OAuth2Accessor accessor) {
    this.cache.storeOAuth2Accessor(accessor);
  }
}
