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
import org.apache.shindig.gadgets.oauth2.OAuth2Token;

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
