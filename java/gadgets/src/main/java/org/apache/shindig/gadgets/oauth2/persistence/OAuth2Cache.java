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
package org.apache.shindig.gadgets.oauth2.persistence;

import java.util.Collection;

import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;

/**
 * Used by {@link OAuth2Store} to cache OAuth2 data.
 * 
 * Default implementation is in-memory HashMaps for shindig.
 * 
 */
public interface OAuth2Cache {
  /**
   * Clears all cached {@link OAuth2Client}s.
   * 
   * @throws OAuth2CacheException
   */
  void clearClients() throws OAuth2CacheException;

  /**
   * Clears all cached {@link OAuth2Token}s.
   * 
   * @throws OAuth2CacheException
   */
  void clearTokens() throws OAuth2CacheException;

  /**
   * Find an {@link OAuth2Client} by {@link Integer} index.
   * 
   * @param index
   * @return
   */
  OAuth2Client getClient(Integer index);

  /**
   * Generate an {@link OAuth2Client} index for the given mapping.
   * 
   * @param gadgetUri
   * @param serviceName
   * @return
   */
  Integer getClientIndex(String gadgetUri, String serviceName);

  /**
   * Find an {@link OAuth2Accessor} by index.
   * 
   * @param index
   * @return
   */
  OAuth2Accessor getOAuth2Accessor(Integer index);

  /**
   * Find an {@link OAuth2Accessor} by the given mapping;
   * 
   * @param gadgetUri
   * @param serviceName
   * @param user
   * @param scope
   * @return
   */
  Integer getOAuth2AccessorIndex(String gadgetUri, String serviceName, String user, String scope);

  /**
   * Find an {@link OAuth2Token} by index.
   * 
   * @param index
   * @return
   */
  OAuth2Token getToken(Integer index);

  /**
   * Returns the {@link Integer} index for the given {@link OAuth2Token}.
   * 
   * @param token
   * @return
   */
  Integer getTokenIndex(OAuth2Token token);

  /**
   * Find an {@link OAuth2Token} by the given scope.
   * 
   * @param gadgetUri
   * @param serviceName
   * @param user
   * @param scope
   * @param type
   * @return
   */
  Integer getTokenIndex(String gadgetUri, String serviceName, String user, String scope,
      OAuth2Token.Type type);

  /**
   * Removes the {@link OAuth2Client} from the cache.
   * 
   * @param index
   * @return the removed client, or <code>null</code> if none was found
   * @throws OAuth2CacheException
   */
  OAuth2Client removeClient(Integer index) throws OAuth2CacheException;

  /**
   * Removes the given {@link OAuth2Accessor} from the cache.
   * 
   * @param accessor
   * @return the removed {@link OAuth2Accessor} or <code>null</code> if none was
   *         found
   */
  OAuth2Accessor removeOAuth2Accessor(OAuth2Accessor accessor);

  /**
   * Removes the given {@link OAuth2Token} from the cache.
   * 
   * @param index
   * @return the removed {@link OAuth2Token} or <code>null</code> if none was
   *         found
   * @throws OAuth2CacheException
   */
  OAuth2Token removeToken(Integer index) throws OAuth2CacheException;

  /**
   * Stores the given client.
   * 
   * @param index
   * @param client
   * @throws OAuth2CacheException
   */
  Integer storeClient(OAuth2Client client) throws OAuth2CacheException;

  /**
   * Store all clients in the collection.
   * 
   * @param clients
   * @throws OAuth2CacheException
   */
  void storeClients(Collection<OAuth2Client> clients) throws OAuth2CacheException;

  /**
   * Stores the given accessor.
   * 
   * @param accessor
   */
  Integer storeOAuth2Accessor(OAuth2Accessor accessor);

  /**
   * Stores the given token and returns it's index.
   */
  Integer storeToken(OAuth2Token token) throws OAuth2CacheException;

  /**
   * Stores all tokens in the collection.
   * 
   * @param tokens
   * @throws OAuth2CacheException
   */
  void storeTokens(Collection<OAuth2Token> tokens) throws OAuth2CacheException;
}
