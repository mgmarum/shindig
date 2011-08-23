/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shindig.gadgets.uri;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;

import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.config.ContainerConfig;
import org.apache.shindig.gadgets.Gadget;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.rewrite.DomWalker;

import java.util.Collection;

/**
 * Default UriManager for Accel servlet.
 * TODO: Add support for multiple accel hosts.
 *
 * @since 2.0.0
 */
public class DefaultAccelUriManager implements AccelUriManager, ContainerConfig.ConfigObserver {
  String accelHost;
  String accelPath;

  ProxyUriManager proxyUriManager;

  @Inject
  public DefaultAccelUriManager(ContainerConfig config,
                                ProxyUriManager proxyUriManager) {
    this.proxyUriManager = proxyUriManager;
    config.addConfigObserver(this, true);
  }
  
  public void containersChanged(
      ContainerConfig config, Collection<String> changed, Collection<String> removed) {
    accelHost = config.getString(AccelUriManager.CONTAINER, PROXY_HOST_PARAM);
    accelPath = config.getString(AccelUriManager.CONTAINER, PROXY_PATH_PARAM);
  }

  public Uri parseAndNormalize(HttpRequest httpRequest) throws GadgetException {
    // Make a gadget object with the accel container.
    Gadget gadget = DomWalker.makeGadget(httpRequest);
    gadget.setContext(new GadgetContext(gadget.getContext()) {
      @Override
      public String getContainer() {
        return AccelUriManager.CONTAINER;
      }
    });

    // Normalize the request url to proxy uri form.
    ProxyUriManager.ProxyUri proxied = looksLikeAccelUri(httpRequest.getUri()) ?
        proxyUriManager.process(httpRequest.getUri()) : new ProxyUriManager.ProxyUri(
        gadget, httpRequest.getUri());
    return proxyUriManager.make(ImmutableList.of(proxied), 0).get(0);
  }

  /**
   * Is the given uri looks like a valid accel uri. If not, it should
   * definitely be normalized.
   * @param requestUri The uri to check.
   * @return True in case the given uri was possibly generated by accel, false
   *   otherwise.
   */
  protected boolean looksLikeAccelUri(Uri requestUri) {
    return accelHost.equals(requestUri.getAuthority()) &&
           accelPath.equals(requestUri.getPath()) &&
           !Strings.isNullOrEmpty(requestUri.getQueryParameter(
                   UriCommon.Param.URL.getKey()));
  }
}
