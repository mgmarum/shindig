package org.apache.shindig.social.core.oauth;

import org.apache.shindig.common.testing.FakeHttpServletRequest;
import org.apache.shindig.common.uri.UriBuilder;
import org.apache.shindig.social.core.oauth2.OAuth2Servlet;
import org.apache.shindig.social.dataservice.integration.AbstractLargeRestfulTests;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletResponse;

import java.io.PrintWriter;
import java.net.URLEncoder;

public class OAuth2ImplicitFlowTest extends AbstractLargeRestfulTests {
  protected OAuth2Servlet servlet = null;
  
  public static final String IMPLICIT_CLIENT_ID = "advancedImplicitClient";
  
  protected static final String REDIRECT_URI = "http://localhost:8080/oauthclients/ImplicitClientHelper.html";
  
  @Before
  @Override
  public void abstractLargeRestfulBefore() throws Exception {
    super.abstractLargeRestfulBefore();
    servlet = new OAuth2Servlet();
    injector.injectMembers(servlet);
  };
  
  
  /**
   * Test retrieving an access token using a public client with a redirect uri
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenWithRedirectParamAndState() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080/oauth2");
    req.setContentType("application/x-www-form-urlencoded");
    req.setPostData("client_id=" + IMPLICIT_CLIENT_ID + "&response_type=token&state=PRESERVEME&redirect_uri="
        +URLEncoder.encode(REDIRECT_URI,"UTF-8"), "UTF-8");
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/authorize");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    Capture<String> redirectURI = new Capture<String>();
    resp.setHeader(EasyMock.eq("Location"), EasyMock.capture(redirectURI));
    resp.setStatus(HttpServletResponse.SC_FOUND);
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String fragment = UriBuilder.parse(redirectURI.getValue()).getFragment();
    assertTrue(redirectURI.getValue().startsWith(REDIRECT_URI));
    assertTrue(fragment.contains("token_type=bearer"));
    assertTrue(fragment.contains("access_token="));
    assertTrue(fragment.contains("expires_in="));
    assertTrue(fragment.contains("state=PRESERVEME"));

    verify();
  }
  
  /**
   * Test retrieving an access token using a public client with redirect uri
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenNoRedirectParam() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080/oauth2");
    req.setContentType("application/x-www-form-urlencoded");
    req.setPostData("client_id=" + IMPLICIT_CLIENT_ID + "&response_type=token", "UTF-8");
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/authorize");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    Capture<String> redirectURI = new Capture<String>();
    resp.setHeader(EasyMock.eq("Location"), EasyMock.capture(redirectURI));
    resp.setStatus(HttpServletResponse.SC_FOUND);
    MockServletOutputStream outputStream = new MockServletOutputStream();
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer).anyTimes();
    replay();
    servlet.service(req, resp);
    writer.flush();
    String fragment = UriBuilder.parse(redirectURI.getValue()).getFragment();
    assertTrue(redirectURI.getValue().startsWith(REDIRECT_URI));
    assertTrue(fragment.contains("token_type=bearer"));
    assertTrue(fragment.contains("access_token="));
    assertTrue(fragment.contains("expires_in="));
    verify();
  }
  
  /**
   * Test attempting to retrieve an access token using a bad redirect URI
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenWithBadRedirect() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080/oauth2");
    req.setContentType("application/x-www-form-urlencoded");
    req.setPostData("client_id=" + IMPLICIT_CLIENT_ID + "&response_type=token&redirect_uri="
        +URLEncoder.encode("BAD_REDIRECT","UTF-8"), "UTF-8");
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

    verify();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
  }
  
  /**
   * Test attempting to retrieve an access token using a bad client id
   * @throws Exception
   */
  @Test
  public void testGetAccessTokenWithBadClientID() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080/oauth2");
    req.setContentType("application/x-www-form-urlencoded");
    req.setPostData("client_id=BAD-ID&response_type=token&redirect_uri="
        +URLEncoder.encode(REDIRECT_URI,"UTF-8"), "UTF-8");
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

    verify();
    String response = new String(outputStream.getBuffer(),"UTF-8");
    assertTrue(response == null || response.equals(""));
  }
  
  
  
}