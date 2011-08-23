package org.apache.shindig.social.core.oauth;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.util.ByteArrayBuffer;
import org.apache.shindig.common.testing.FakeHttpServletRequest;
import org.apache.shindig.social.core.oauth2.OAuth2Servlet;
import org.apache.shindig.social.dataservice.integration.AbstractLargeRestfulTests;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import java.io.PrintWriter;
import java.net.URI;
import java.net.URLEncoder;
import java.util.UUID;

public class OAuth2Test extends AbstractLargeRestfulTests{

  protected static final String SIMPLE_ACCESS_TOKEN = "TEST_TOKEN";
  protected static final String PUBLIC_CLIENT_ID = "testClient";
  protected static final String PUBLIC_AUTH_CODE = "testClient_authcode_1";
  protected static final String CONF_CLIENT_ID = "advancedAuthorizationCodeClient";
  protected static final String CONF_CLIENT_SECRET = "advancedAuthorizationCodeClient_secret";
  protected static final String CONF_AUTH_CODE = "advancedClient_authcode_1";
  
  protected OAuth2Servlet servlet = null;
  
  @Before
  @Override
  public void abstractLargeRestfulBefore() throws Exception {
    super.abstractLargeRestfulBefore();
    servlet = new OAuth2Servlet();
    injector.injectMembers(servlet);
  };
  
  /**
   * Test retrieving an access token using a public client
   * @throws Exception
   */
  @Test
  public void testGetAccessToken() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080/oauth2");
    req.setContentType("application/x-www-form-urlencoded");
    req.setPostData("client_id=" + PUBLIC_CLIENT_ID + "&grant_type=authorization_code&redirect_uri="
        +URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
        +"&code="+PUBLIC_AUTH_CODE, "UTF-8");
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.setStatus(HttpServletResponse.SC_OK);
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();

    JSONObject tokenResponse = new JSONObject(new String(outputStream.getBuffer(),"UTF-8"));
    
    assertEquals("bearer",tokenResponse.getString("token_type"));
    assertNotNull(tokenResponse.getString("access_token"));
    assertTrue(tokenResponse.getLong("expires_in") > 0);
    verify();
  }
  
  /**
   * Test retrieving an authorization code using a public client
   * @throws Exception
   */
  @Test
  public void testGetAuthorizationCode() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080/oauth2");
    req.setContentType("application/x-www-form-urlencoded");
    req.setPostData("client_id=" + PUBLIC_CLIENT_ID + "&response_type=code&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8"),"UTF-8");
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/authorize");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    Capture<String> redirectURI = new Capture<String>();
    resp.setHeader(EasyMock.eq("Location"), EasyMock.capture(redirectURI));
    resp.setStatus(EasyMock.eq(HttpServletResponse.SC_FOUND));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
    assertTrue(redirectURI.getValue().startsWith("http://localhost:8080/oauthclients/AuthorizationCodeClient?code="));
    String code = redirectURI.getValue().substring(redirectURI.getValue().indexOf("=")+1);
    UUID id = UUID.fromString(code);
    assertTrue(id != null);
  }
  
  /**
   * Test retrieving an authorization code using a public client that preserves state
   * @throws Exception
   */
  @Test
  public void testGetAuthorizationCodePreserveState() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + PUBLIC_CLIENT_ID + "&response_type=code&state=PRESERVEME&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8"));
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/authorize");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    Capture<String> redirectURI = new Capture<String>();
    resp.setHeader(EasyMock.eq("Location"), EasyMock.capture(redirectURI));
    resp.setStatus(EasyMock.eq(HttpServletResponse.SC_FOUND));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
    assertTrue(redirectURI.getValue().startsWith("http://localhost:8080/oauthclients/AuthorizationCodeClient?code="));
    URI uri = new URI(redirectURI.getValue());
    assertTrue(uri.getQuery().contains("state=PRESERVEME"));
    assertTrue(uri.getQuery().contains("code="));
  }
  
  /**
   * Test retrieving an authorization code using a confidential client
   * 
   * Client authentication is not required for confidential clients accessing 
   * the authorization endpoint
   * 
   * @throws Exception
   */
  @Test
  public void testGetAuthorizationCodeConfidential() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&response_type=code&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8"));
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/authorize");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    Capture<String> redirectURI = new Capture<String>();
    resp.setHeader(EasyMock.eq("Location"), EasyMock.capture(redirectURI));
    resp.setStatus(EasyMock.eq(HttpServletResponse.SC_FOUND));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
    assertTrue(redirectURI.getValue().startsWith("http://localhost:8080/oauthclients/AuthorizationCodeClient?code="));
    String code = redirectURI.getValue().substring(redirectURI.getValue().indexOf("=")+1);
    UUID id = UUID.fromString(code);
    assertTrue(id != null);
  }
  
  /**
   * Test retrieving an authorization code using a confidential client without setting redirect URI
   * 
   * The redirect URI is registered with this client, so omitting it should still generate a response
   * using the registered redirect URI.
   * 
   * @throws Exception
   */
  @Test
  public void testGetAuthorizationCodeNoRedirect() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&response_type=code");
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/authorize");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    Capture<String> redirectURI = new Capture<String>();
    resp.setHeader(EasyMock.eq("Location"), EasyMock.capture(redirectURI));
    Capture<Integer> respCode = new Capture<Integer>();
    resp.setStatus(EasyMock.capture(respCode));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
    assertEquals((Integer)302,respCode.getValue());
    assertTrue(redirectURI.getValue().startsWith("http://localhost:8080/oauthclients/AuthorizationCodeClient?code="));
    String code = redirectURI.getValue().substring(redirectURI.getValue().indexOf("=")+1);
    UUID id = UUID.fromString(code);
    assertTrue(id != null);
  }
  
  /**
   * Test retrieving an authorization code using a confidential client with a bad redirect URI
   * 
   * The redirect URI is registered with this client, so passing a redirect that doesn't match the
   * registered value should generate an error per the OAuth 2.0 spec.
   * 
   * See Section 3.1.2.3 under http://tools.ietf.org/html/draft-ietf-oauth-v2-20#section-3.1.2
   * 
   * 
   * @throws Exception
   */
  @Test
  public void testGetAuthorizationCodeBadRedirect() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&response_type=code&redirect_uri=" 
          + URLEncoder.encode("http://example.org/redirect/","UTF-8"));
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/authorize");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.sendError(EasyMock.eq(HttpServletResponse.SC_FORBIDDEN), EasyMock.anyObject(String.class));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
  }
  
  /**
   * Test retrieving an auth code and using it to generate an access token
   * 
   * @throws Exception
   */
  @Test
  public void testConfidentialAuthCodeFlow() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&response_type=code&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8"));
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/authorize");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    Capture<String> redirectURI = new Capture<String>();
    resp.setHeader(EasyMock.eq("Location"), EasyMock.capture(redirectURI));
    resp.setStatus(EasyMock.eq(HttpServletResponse.SC_FOUND));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
    assertTrue(redirectURI.getValue().startsWith("http://localhost:8080/oauthclients/AuthorizationCodeClient?code="));
    String code = redirectURI.getValue().substring(redirectURI.getValue().indexOf("=")+1);
    UUID id = UUID.fromString(code);
    assertTrue(id != null);
    
    reset();
    
    
    req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&grant_type=authorization_code&redirect_uri="
          + URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
          + "&code=" + code + "&client_secret=" + CONF_CLIENT_SECRET);
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    resp = mock(HttpServletResponse.class);
    resp.setStatus(HttpServletResponse.SC_OK);
    outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();

    JSONObject tokenResponse = new JSONObject(new String(outputStream.getBuffer(),"UTF-8"));
    
    assertEquals("bearer",tokenResponse.getString("token_type"));
    assertNotNull(tokenResponse.getString("access_token"));
    assertTrue(tokenResponse.getLong("expires_in") > 0);
    verify();
    
  }
  
  /**
   * Test using URL parameter to pass client secret to authenticate client
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenConfidentialClientParams() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&grant_type=authorization_code&redirect_uri="
          + URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
          + "&code=" + CONF_AUTH_CODE + "&client_secret=" + CONF_CLIENT_SECRET);
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.setStatus(HttpServletResponse.SC_OK);
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();

    JSONObject tokenResponse = new JSONObject(new String(outputStream.getBuffer(),"UTF-8"));
    
    assertEquals("bearer",tokenResponse.getString("token_type"));
    assertNotNull(tokenResponse.getString("access_token"));
    assertTrue(tokenResponse.getLong("expires_in") > 0);
    verify();
  }
  
  /**
   * Test using basic authentication scheme for client authentication
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenConfidentialClientBasicAuth() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&grant_type=authorization_code&redirect_uri="
          + URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
          + "&code=" + CONF_AUTH_CODE);
    req.setHeader("Authorization","Basic "+Base64.encodeBase64String((CONF_CLIENT_ID+":"+CONF_CLIENT_SECRET).getBytes("UTF-8")));
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.setStatus(HttpServletResponse.SC_OK);
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();

    JSONObject tokenResponse = new JSONObject(new String(outputStream.getBuffer(),"UTF-8"));
    
    assertEquals("bearer",tokenResponse.getString("token_type"));
    assertNotNull(tokenResponse.getString("access_token"));
    assertTrue(tokenResponse.getLong("expires_in") > 0);
    verify();
  }
  
  /**
   * Incorrect client ID used in Basic Authorization header
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenConfClientBasicAuthBadID() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&grant_type=authorization_code&redirect_uri="
          + URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
          + "&code=" + CONF_AUTH_CODE);
    req.setHeader("Authorization","Basic "+Base64.encodeBase64String(("BAD_ID:"+CONF_CLIENT_SECRET).getBytes("UTF-8")));
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.sendError(EasyMock.eq(HttpServletResponse.SC_FORBIDDEN), EasyMock.anyObject(String.class));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
  }
  
  /**
   * Test attempting to get an access token using a bad client secret with a confidential client. 
   */
  @Test
  public void testGetAccessTokenBadConfidentialClientParams() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + CONF_CLIENT_ID + "&grant_type=authorization_code&redirect_uri="
          + URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
          + "&code=" + CONF_AUTH_CODE + "&client_secret=BAD_SECRET");
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.sendError(EasyMock.eq(HttpServletResponse.SC_FORBIDDEN), EasyMock.anyObject(String.class));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
  }
  
  
  /**
   * Test attempting to get an access token with an unregistered client ID
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenBadClient() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=BAD_CLIENT&grant_type=authorization_code&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
          +"&code="+PUBLIC_AUTH_CODE);
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.sendError(EasyMock.eq(HttpServletResponse.SC_FORBIDDEN), EasyMock.anyObject(String.class));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
  }
  
  
  /**
   * Test attempting to get an access token with a bad grant type
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenBadGrantType() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id="+PUBLIC_CLIENT_ID+"&grant_type=BAD_GRANT&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
          +"&code="+PUBLIC_AUTH_CODE);
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.sendError(EasyMock.eq(HttpServletResponse.SC_FORBIDDEN), EasyMock.anyObject(String.class));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
  }
  
  /**
   * Test attempting to get an access token with an invalid authorization code
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenBadAuthCode() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + PUBLIC_CLIENT_ID + "&grant_type=authorization_code&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/AuthorizationCodeClient","UTF-8")
          +"&code=BAD-CODE-OMG");
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    resp.sendError(EasyMock.eq(HttpServletResponse.SC_FORBIDDEN), EasyMock.anyObject(String.class));
    MockServletOutputStream outputStream = new MockServletOutputStream();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
    verify();
  }
  
  /**
   * Used to capture the raw request response provided by servlet
   *
   */
  private class MockServletOutputStream extends ServletOutputStream {
    private ByteArrayBuffer buffer = new ByteArrayBuffer(1024);

    @Override
    public void write(int b) {
      buffer.append(b);
    }

    public byte[] getBuffer() {
      return buffer.toByteArray();
    }
  }

}
