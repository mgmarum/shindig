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

import java.util.Set;

import org.apache.shindig.gadgets.oauth2.OAuth2Token;

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
