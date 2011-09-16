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

import java.io.Serializable;

/**
 * Contains all relevant data for a token.
 * 
 * OAuth2Token implementations should be {@link Serializable} to facilitate
 * cluster storage and caching across the various phases of OAuth 2.0 flows.
 * 
 * OAuth2Tokens are stored in the {@link OAuth2Store}, they may be held in
 * memory or in another persistence layer.
 * 
 */
public interface OAuth2Token extends Serializable {
  public enum Type {
    ACCESS, REFRESH
  }

  /**
   * Not very useful, but store just in case.
   * 
   * @return the length (in seconds) when the token expires
   */
  public int getExpiresIn();

  /**
   * 
   * @return uri of the gadget the token applies to
   */
  public String getGadgetUri();

  /**
   * 
   * @return serviceName (in gadget spec) the token applies to
   */
  public String getServiceName();

  /**
   * See {@link http://tools.ietf.org/html/draft-ietf-oauth-v2-21#section-3.3}
   * 
   * @return scope the token applies to, or "" for no scope
   */
  public String getScope();

  /**
   * 
   * @return the token secret (unencrypted or signed)
   */
  public String getSecret();

  /**
   * 
   * @return type of this token e.g. "Bearer"
   */
  public String getTokenType();

  /**
   * 
   * @return if this is an Type.ACCESS or Type.REFRESH token
   */
  public Type getType();

  /**
   * 
   * @return shindig user the token was issued for
   */
  public String getUser();

  /**
   * Setter for expiresIn field
   * 
   * @param expiresIn
   */
  public void setExpiresIn(int expiresIn);

  /**
   * Setter for gadgetUri field
   * 
   * @param gadgetUri
   */
  public void setGadgetUri(String gadgetUri);

  /**
   * Setter for serviceName field
   * 
   * @param serviceName
   */
  public void setServiceName(String serviceName);

  /**
   * Setter for scope field
   * 
   * @param scope
   */
  public void setScope(String scope);

  /**
   * Setter for secret property
   * 
   * @param secret
   * @throws OAuth2RequestException
   */
  public void setSecret(String secret) throws OAuth2RequestException;

  /**
   * Setter for tokenType property
   * 
   * @param tokenType
   */
  public void setTokenType(String tokenType);

  /**
   * Setter for type property
   * 
   * @param type
   */
  public void setType(Type type);

  /**
   * Setter for user property
   * 
   * @param user
   */
  public void setUser(String user);
}
