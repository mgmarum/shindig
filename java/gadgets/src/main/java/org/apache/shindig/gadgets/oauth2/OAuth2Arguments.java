/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
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

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Arguments {
  private static final String SERVICE_PARAM = "OAUTH_SERVICE_NAME";
  private static final String BYPASS_SPEC_CACHE_PARAM = "bypassSpecCache";
  
  private final String serviceName;
  private final boolean bypassSpecCache;
  private final Map<String, String> requestOptions = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
      
  public OAuth2Arguments(final AuthType auth, final HttpServletRequest request)
      throws GadgetException {
    this.serviceName = OAuth2Arguments.getRequestParam(request, OAuth2Arguments.SERVICE_PARAM, "");
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
    this.bypassSpecCache = orig.bypassSpecCache;
    this.requestOptions.putAll(orig.requestOptions);
  }
  
  public String getServiceName() {
    return serviceName;
  }

  public boolean getBypassSpecCache() {
    return this.bypassSpecCache;
  }
  
  
  public int hashCode() {
    return Objects.hashCode(this.bypassSpecCache, this.serviceName);
  }

  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof OAuth2Arguments)) {
      return false;
    }

    final OAuth2Arguments other = (OAuth2Arguments) obj;
    return ((this.bypassSpecCache == other.getBypassSpecCache()) && (this.serviceName == other.getServiceName()));
  }
}