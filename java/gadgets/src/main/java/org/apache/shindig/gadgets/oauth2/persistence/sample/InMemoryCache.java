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
package org.apache.shindig.gadgets.oauth2.persistence.sample;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2CacheException;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Client;

import com.google.inject.Inject;
import com.google.inject.Singleton;

/**
 * 
 * {@link OAuth2Cache} implementation using in-memory {@link HashMap}s.
 * 
 */
@Singleton
public class InMemoryCache implements OAuth2Cache {
  private final static String OAUTH2_PREFIX = "OAUTH2_";

  private final static String OAUTH2_TOKEN_PREFIX = InMemoryCache.OAUTH2_PREFIX + "TOKEN_";
  private final static String OAUTH2_CLIENT_PREFIX = InMemoryCache.OAUTH2_PREFIX + "CLIENT_";

  private final Map<Integer, OAuth2Token> tokens;
  private final Map<Integer, OAuth2Client> clients;
  private final Map<Integer, OAuth2Accessor> accessors;

  @Inject
  InMemoryCache() {
    this.tokens = Collections.synchronizedMap(new HashMap<Integer, OAuth2Token>());
    this.clients = Collections.synchronizedMap(new HashMap<Integer, OAuth2Client>());
    this.accessors = Collections.synchronizedMap(new HashMap<Integer, OAuth2Accessor>());
  }

  public Integer getTokenIndex(final OAuth2Token token) {
    if (token != null) {
      return this.getTokenIndex(token.getGadgetUri(), token.getServiceName(), token.getUser(),
          token.getScope(), token.getType());
    }

    return null;
  }

  public Integer getTokenIndex(final String gadgetUri, final String serviceName, final String user,
      final String scope, final OAuth2Token.Type type) {
    return Integer.valueOf((InMemoryCache.OAUTH2_TOKEN_PREFIX + ":" + gadgetUri + ":" + serviceName
        + ":" + user + ":" + scope + ":" + type.name()).hashCode());
  }

  public OAuth2Token getToken(final Integer index) {
    return this.tokens.get(index);
  }

  public Integer storeToken(final OAuth2Token token) throws OAuth2CacheException {
    if (token != null) {
      final Integer index = this.getTokenIndex(token);
      this.tokens.put(index, token);
      return index;
    }

    return null;
  }

  public void storeTokens(final Collection<OAuth2Token> tokens) throws OAuth2CacheException {
    for (final OAuth2Token token : tokens) {
      this.tokens.put(
          this.getTokenIndex(token.getServiceName(), token.getGadgetUri(), token.getUser(),
              token.getScope(), token.getType()), token);
    }
  }

  public OAuth2Token removeToken(final Integer index) throws OAuth2CacheException {
    return this.tokens.remove(index);
  }

  public void clearTokens() throws OAuth2CacheException {
    this.tokens.clear();
  }

  public Integer getClientIndex(final String gadgetUri, final String serviceName) {
    return Integer
        .valueOf((InMemoryCache.OAUTH2_CLIENT_PREFIX + ":" + gadgetUri + ":" + serviceName)
            .hashCode());
  }

  public OAuth2Client getClient(final Integer index) {
    final OAuth2Client ret = this.clients.get(index);
    return ret;
  }

  public Integer storeClient(final OAuth2Client client) throws OAuth2CacheException {
    if (client != null) {
      final Integer index = this.getClientIndex(client.getGadgetUri(), client.getServiceName());
      this.clients.put(index, client);
    }

    return null;
  }

  public void storeClients(final Collection<OAuth2Client> clients) throws OAuth2CacheException {
    for (final OAuth2Client client : clients) {
      this.clients.put(this.getClientIndex(client.getGadgetUri(), client.getServiceName()), client);
    }
  }

  public OAuth2Client removeClient(final Integer index) throws OAuth2CacheException {
    return this.clients.remove(index);
  }

  public void clearClients() throws OAuth2CacheException {
    this.clients.clear();
  }

  public Integer getOAuth2AccessorIndex(final String gadgetUri, final String serviceName,
      final String user, final String scope) {
    return Integer.valueOf((gadgetUri + ":" + serviceName + ":" + ":" + user + ":" + scope)
        .hashCode());
  }

  public OAuth2Accessor removeOAuth2Accessor(final OAuth2Accessor accessor) {
    return this.accessors.remove(accessor);
  }

  public Integer storeOAuth2Accessor(final OAuth2Accessor accessor) {
    if (accessor != null) {
      final Integer index = this.getOAuth2AccessorIndex(accessor.getGadgetUri(),
          accessor.getServiceName(), accessor.getUser(), accessor.getScope());
      this.accessors.put(index, accessor);
      return index;
    }

    return null;
  }

  public OAuth2Accessor getOAuth2Accessor(final Integer index) {
    OAuth2Accessor ret = null;
    if (index != null) {
      ret = this.accessors.get(index);
    }

    return ret;
  }
}
