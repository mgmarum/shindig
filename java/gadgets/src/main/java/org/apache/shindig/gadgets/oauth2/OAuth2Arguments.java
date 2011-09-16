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
package org.apache.shindig.gadgets.oauth2;

import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;

import org.apache.shindig.gadgets.AuthType;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.spec.RequestAuthenticationInfo;

import com.google.common.base.Objects;

/**
 * Arguments to an OAuth2 fetch sent by the client.
 */
public class OAuth2Arguments {
  private static final String SERVICE_PARAM = "OAUTH_SERVICE_NAME";
  private static final String SCOPE_PARAM = "OAUTH_SCOPE";
  private static final String BYPASS_SPEC_CACHE_PARAM = "bypassSpecCache";

  private final String serviceName;
  private final boolean bypassSpecCache;
  private final String scope;

  private final Map<String, String> requestOptions = new TreeMap<String, String>(
      String.CASE_INSENSITIVE_ORDER);

  /**
   * Public constructor to parse OAuth2Arguments from a {@link HttpServletRequest}

   * @param request {@link HttpServletRequest} that came into the server
   * @throws GadgetException
   */
  public OAuth2Arguments(final HttpServletRequest request) throws GadgetException {
    this.serviceName = OAuth2Arguments.getRequestParam(request, OAuth2Arguments.SERVICE_PARAM, "");
    this.scope = OAuth2Arguments.getRequestParam(request, OAuth2Arguments.SCOPE_PARAM, "");
    this.bypassSpecCache = "1".equals(OAuth2Arguments.getRequestParam(request,
        OAuth2Arguments.BYPASS_SPEC_CACHE_PARAM, null));
    final Enumeration<String> params = this.getParameterNames(request);
    while (params.hasMoreElements()) {
      final String name = params.nextElement();
      this.requestOptions.put(name, request.getParameter(name));
    }
  }

  @SuppressWarnings("unchecked")
  private Enumeration<String> getParameterNames(final HttpServletRequest request) {
    return request.getParameterNames();
  }

  public OAuth2Arguments(final RequestAuthenticationInfo info) throws GadgetException {
    this(info.getAuthType(), info.getAttributes());
  }

  public OAuth2Arguments(final AuthType auth, final Map<String, String> map) throws GadgetException {
    this.requestOptions.putAll(map);
    this.serviceName = OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.SERVICE_PARAM, "");
    this.scope = OAuth2Arguments.getAuthInfoParam(this.requestOptions, OAuth2Arguments.SCOPE_PARAM,
        "");
    this.bypassSpecCache = "1".equals(OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.BYPASS_SPEC_CACHE_PARAM, null));
  }

  private static String getRequestParam(final HttpServletRequest request, final String name,
      final String def) {
    String val = request.getParameter(name);
    if (val == null) {
      val = def;
    }
    return val;
  }

  private static String getAuthInfoParam(final Map<String, String> attrs, final String name,
      final String def) {
    String val = attrs.get(name);
    if (val == null) {
      val = def;
    }
    return val;
  }

  public OAuth2Arguments(final OAuth2Arguments orig) {
    this.serviceName = orig.serviceName;
    this.scope = orig.scope;
    this.bypassSpecCache = orig.bypassSpecCache;
    this.requestOptions.putAll(orig.requestOptions);
  }

  public String getServiceName() {
    return this.serviceName;
  }

  public String getScope() {
    return this.scope;
  }

  public boolean getBypassSpecCache() {
    return this.bypassSpecCache;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(this.bypassSpecCache, this.serviceName);
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof OAuth2Arguments)) {
      return false;
    }

    final OAuth2Arguments other = (OAuth2Arguments) obj;
    return ((this.bypassSpecCache == other.getBypassSpecCache()) && (this.serviceName == other
        .getServiceName()));
  }
}