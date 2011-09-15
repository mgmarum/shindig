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

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.common.servlet.GuiceServletContextListener;

import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.name.Named;

/**
 * Filter denies request unless a valid Bearer token is attached to request
 * 
 * This is intended as an example of a generic OAuth2 Filter that could be used in front of any servlet providing protected resources.
 * 
 * The OAuth2AuthenticationHandler is the filtering mechanism that plugs into Shindig
 * 
 * @author mgmarum
 *
 */
public class OAuth2Filter implements Filter {
  public static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";
  protected Injector injector;
  protected transient boolean initialized = false;
  
  protected OAuth2Service dataStore = null;
  private String realm;
  
  @Inject
  protected void setOAuth2Service(OAuth2Service store){
    dataStore = store;
  }

  /**
   * Going to load DataStore from Guice binding
   */
  public void init(FilterConfig config) throws ServletException {
    ServletContext context = config.getServletContext();
    injector = (Injector) context.getAttribute(GuiceServletContextListener.INJECTOR_ATTRIBUTE);
    if (injector == null) {
      injector = (Injector) context.getAttribute(GuiceServletContextListener.INJECTOR_NAME);
      if (injector == null) {
        throw new UnavailableException(
            "Guice Injector not found! Make sure you registered " +
                GuiceServletContextListener.class.getName() + " as a listener");
      }
    }
    injector.injectMembers(this);
    initialized = true;
  }
  
  @Inject(optional = true)
  public void setAuthenticationRealm(@Named("shindig.authentication.realm") String realm) {
    this.realm = realm;
  }

  
  /**
   * Totally incomplete...
   * TODO Finish.
   */
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if(request instanceof HttpServletRequest){
      HttpServletRequest httpReq = (HttpServletRequest)request;
      HttpServletResponse httpResp = (HttpServletResponse)response;
      String bearerToken = OAuth2Utils.fetchBearerTokenFromHttpRequest(httpReq);
      if(bearerToken == null || bearerToken.equals("")){
        httpResp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResp.addHeader(WWW_AUTHENTICATE_HEADER, String.format("Bearer realm=\"%s\"", realm));
        return;
      }
    }
    chain.doFilter(request, response);
  }
  
  

  public void destroy() {

  }

}
