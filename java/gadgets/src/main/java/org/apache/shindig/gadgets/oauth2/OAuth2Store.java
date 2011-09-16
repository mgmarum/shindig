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

import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.servlet.OAuth2CallbackServlet;

/**
 * Interface to an OAuth 2.0 Data Store. A shindig gadget server can act as an
 * OAuth 2.0 consumer, using OAuth 2.0 tokens to talk to OAuth 2.0 service
 * providers on behalf of the gadgets it is proxying requests for. An OAuth 2.0
 * consumer needs to permanently store gadgets it has collected, and retrieve
 * the appropriate tokens when proxying a request for a gadget.
 * 
 * Access and Refresh {@link OAuth2Token} may be store in memory or pesisted out
 * to a file system or database.
 * 
 * OAuth2Store implementors are responsible for handling the gadgeturi,
 * serviceName, user, scope mappings in the manor most effective for their
 * environment.
 * 
 * {@link OAuth2Accessor} storage should be cluster safe so it can be referenced
 * by {@link OAuth2CallbackServlet}
 */
public interface OAuth2Store {

  /**
   * Clears any in-memory caching of OAuth2Accessors or Tokens.
   * 
   * @return <code>true</code> if the clear succeeded
   * 
   * @throws GadgetException
   *           if the clear could not happen
   */
  public boolean clearCache() throws GadgetException;

  /**
   * Creates, but does not store, an {@link OAuth2Token}. The token can then be
   * initialized and stored.
   * 
   * @return a new {@link OAuth2Token}
   */
  public OAuth2Token createToken();

  /**
   * Given an index, see {@link OAuth2Store.getOAuth2AccessorIndex}, the store
   * will return the {@link OAuth2Accessor} if it exists in storage but will not
   * create a new one.
   * 
   * @param index
   *          {@link Integer} index of the accessor to get
   * @return the {@link OAuth2Accessor} or <code>null</code> if it cannot be
   *         located
   */
  public OAuth2Accessor getOAuth2Accessor(Integer index);

  /**
   * Will look for an accessor with the supplied mapping and return it. If one
   * is not already stored a new one will be created and stored.
   * 
   * @param gadgetUri
   *          {@link String} URI of the gadget issuing the request
   * @param serviceName
   *          {@link String} name of the OAuth2 service from the gadget spec
   * @param user
   *          {@link String user} userid of the page viewer
   * @param scope
   *          {@link String} optional scope of the request. Supplied by the
   *          request or the gadget spec
   * @return the {@link OAuth2Accessor} , never <code>null</code>
   * @throws GadgetException
   *           if a lookup or creation error occurs
   */
  public OAuth2Accessor getOAuth2Accessor(String gadgetUri, String serviceName, String user,
      String scope) throws GadgetException;

  /**
   * Takes an accessor mapping and turns it into an {@link Integer} index.
   * 
   * @param gadgetUri
   *          {@link String} URI of the gadget issuing the request
   * @param serviceName
   *          {@link String} name of the OAuth2 service from the gadget spec
   * @param user
   *          {@link String user} userid of the page viewer
   * @param scope
   *          {@link String} optional scope of the request. Supplied by the
   *          request or the gadget spec
   * @return {@link Integer} index representing the mappign
   */
  public Integer getOAuth2AccessorIndex(String gadgetUri, String serviceName, String user,
      String scope);

  /**
   * Gets a token, if it exists, from the store.
   * 
   * @param gadgetUri
   *          {@link String} URI of the gadget issuing the request
   * @param serviceName
   *          {@link String} name of the OAuth2 service from the gadget spec
   * @param user
   *          {@link String user} userid of the page viewer
   * @param scope
   *          {@link String} optional scope of the request. Supplied by the
   *          request or the gadget spec
   * @param type
   *          {@link Type} if the token, ACCESS or REFRESH
   * @return the {@link OAuth2Token} for the supplied mapping, <code>null</code>
   *         if it isn't stored
   * @throws GadgetException
   *           if something goes wrong
   */
  public OAuth2Token getToken(String gadgetUri, String serviceName, String user, String scope,
      OAuth2Token.Type type) throws GadgetException;

  /**
   * Cues the store to clear it's current state and reload from persistence.
   * 
   * @return
   * @throws GadgetException
   */
  public boolean init() throws GadgetException;

  /**
   * Removes an {@link OAuth2Accessor} from the store.
   * 
   * @param accessor
   *          to remove
   * @return the accessor that was removed, or <code>null</code> if the accessor
   *         was already removed
   */
  public OAuth2Accessor removeOAuth2Accessor(OAuth2Accessor accessor);

  /**
   * Removes an {@link OAuth2Token} from the store.
   * 
   * @param token
   *          to remove
   * @return the token that was removed, or <code>null</code> if the token was
   *         already removed\
   * @throws GadgetException
   *           if something goes wrong
   */
  public OAuth2Token removeToken(OAuth2Token token) throws GadgetException;

  /**
   * Either inserts updates an {@link OAuth2Token} in the store.
   * 
   * @param token
   *          to store
   * @throws GadgetException
   *           if something goes wrong
   */
  public void setToken(OAuth2Token token) throws GadgetException;

  /**
   * Either inserts updates an {@link OAuth2Accessor} in the store.
   * 
   * @param accessor
   *          to store
   */
  public void storeOAuth2Accessor(OAuth2Accessor accessor);
}
