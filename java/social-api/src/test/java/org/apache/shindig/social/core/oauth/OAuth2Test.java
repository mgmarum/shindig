package org.apache.shindig.social.core.oauth;

import org.apache.http.util.ByteArrayBuffer;
import org.apache.shindig.common.testing.FakeHttpServletRequest;
import org.apache.shindig.social.core.oauth2.OAuth2Servlet;
import org.apache.shindig.social.dataservice.integration.AbstractLargeRestfulTests;
import org.easymock.EasyMock;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import java.io.PrintWriter;
import java.net.URLEncoder;

public class OAuth2Test extends AbstractLargeRestfulTests{

  protected static final String SIMPLE_ACCESS_TOKEN = "TEST_TOKEN";
  protected static final String PUBLIC_CLIENT_ID = "testClient";
  protected static final String PUBLIC_AUTH_CODE = "testClient_authcode_1";
  
  protected OAuth2Servlet servlet = null;
  
  @Before
  @Override
  public void abstractLargeRestfulBefore() throws Exception {
    super.abstractLargeRestfulBefore();
    servlet = new OAuth2Servlet();
    injector.injectMembers(servlet);
  };
  
  @Test
  public void testGetAccessToken() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + PUBLIC_CLIENT_ID + "&grant_type=authorization_code&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/OpenSocialClient","UTF-8")
          +"&code="+PUBLIC_AUTH_CODE);
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
  
  @Test
  public void testGetAccessTokenBadClient() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=BAD_CLIENT&grant_type=authorization_code&redirect_uri="
          +URLEncoder.encode("http://localhost:8080/oauthclients/OpenSocialClient","UTF-8")
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
