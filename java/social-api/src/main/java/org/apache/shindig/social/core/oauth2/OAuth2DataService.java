/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.apache.shindig.social.core.oauth2;

/**
 * Services to support the management of data for the OAuth 2.0 specification.
 * Includes management of clients, authorization codes, access tokens, and
 * refresh tokens.
 * 
 * TODO: client registration services?
 */
public interface OAuth2DataService {

  /**
   * Retrieves a pre-registered client by ID.
   */
  public OAuth2Client getClient(String clientId);
  
  /**
   * Retrieves an authorization code by its value.
   */
  public OAuth2Code getAuthorizationCode(String clientId, String authCode);
  
  /**
   * Registers an authorization code with a client.
   */
  public void registerAuthorizationCode(String clientId, OAuth2Code authCode);
  
  /**
   * Unregisters an authorization code with a client.
   */
  public void unregisterAuthorizationCode(String clientId, String authCode);
  
  /**
   * Retrieves an access token by its value.
   */
  public OAuth2Code getAccessToken(String accessToken);
  
  /**
   * Registers an access token with a client.
   */
  public void registerAccessToken(String clientId, OAuth2Code accessToken);
  
  /**
   * Unregisters an access token with a client.
   */
  public void unregisterAccessToken(String clientId, String accessToken);
  
  /**
   * Retrieves a refresh token by its value.
   */
  public OAuth2Code getRefreshToken(String refreshToken);
  
  /**
   * Registers a refresh token with a client.
   */
  public void registerRefreshToken(String clientId, OAuth2Code refreshToken);
  
  /**
   * Unregisters a refresh token with a client.
   */
  public void unregisterRefreshToken(String clientId, String refreshToken);
}
