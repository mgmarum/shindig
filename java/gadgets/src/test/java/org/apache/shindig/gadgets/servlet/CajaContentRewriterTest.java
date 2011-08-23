/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shindig.gadgets.servlet;

import com.google.caja.plugin.PluginCompiler;
import com.google.caja.plugin.PluginMeta;
import com.google.caja.reporting.BuildInfo;
import com.google.caja.reporting.MessageQueue;
import com.google.common.collect.ImmutableList;
import org.apache.shindig.common.cache.CacheProvider;
import org.apache.shindig.common.cache.LruCacheProvider;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.Gadget;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.RequestPipeline;
import org.apache.shindig.gadgets.parse.DefaultHtmlSerializer;
import org.apache.shindig.gadgets.parse.GadgetHtmlParser;
import org.apache.shindig.gadgets.parse.ParseModule;
import org.apache.shindig.gadgets.parse.caja.CajaHtmlParser;
import org.apache.shindig.gadgets.parse.nekohtml.NekoSimplifiedHtmlParser;
import org.apache.shindig.gadgets.rewrite.MutableContent;
import org.apache.shindig.gadgets.rewrite.RewriterTestBase;
import org.apache.shindig.gadgets.uri.ProxyUriManager;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.DOMImplementation;

import java.util.List;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertTrue;

public class CajaContentRewriterTest extends RewriterTestBase {
  private List<GadgetHtmlParser> parsers;
  private CajaContentRewriter rewriter;
  private ProxyUriManager proxyUriManager;
  
  @Before
  public void setUp() throws Exception {
    super.setUp();

    DOMImplementation dom = new ParseModule.DOMImplementationProvider().get();
    GadgetHtmlParser neko =  new NekoSimplifiedHtmlParser(dom);
    GadgetHtmlParser caja =  new CajaHtmlParser(dom);

    // FIXME: Caja has trouble with the NekoSimplifiedHtmlParser
    // Disabling neko for now
    parsers = ImmutableList.of(/*neko, */caja);

    CacheProvider lru = new LruCacheProvider(3);
    RequestPipeline pipeline = EasyMock.createNiceMock(RequestPipeline.class);
    DefaultHtmlSerializer defaultSerializer = new DefaultHtmlSerializer();
    proxyUriManager = EasyMock.createNiceMock(ProxyUriManager.class);
    rewriter = new CajaContentRewriter(lru, pipeline, defaultSerializer, proxyUriManager) {
      @Override
      protected PluginCompiler makePluginCompiler(PluginMeta m, MessageQueue q) {
        BuildInfo bi = EasyMock.createNiceMock(BuildInfo.class);
        expect(bi.getBuildInfo()).andReturn("bi").anyTimes();
        expect(bi.getBuildTimestamp()).andReturn("0").anyTimes();
        expect(bi.getBuildVersion()).andReturn("0").anyTimes();
        expect(bi.getCurrentTime()).andReturn(0L).anyTimes();
        replay(bi);
        return new PluginCompiler(bi, m, q);
      }
    };
  }

  @Test
  public void testErrorDuringRewrite() throws Exception {
    String markup = "<script>var x={}; with(x) {};</script>";
    String expected = "<html><head></head><body><ul class=\"gadgets-messages\">";

    List<String> messages = ImmutableList.of(
            "folding element html into parent",
            "folding element head into parent",
            "folding element body into parent",
            "&#34;with&#34; blocks are not allowed");
    testMarkup(markup, expected, messages);
  }

  @Test
  public void testCssExpression() throws Exception {
    String markup = "<div style='top:expression(alert(0), 0)'>test</div>";
    String expected =
        "<div style=\"\">test</div>";

    List<String> messages = ImmutableList.of(
            "folding element html into parent",
            "folding element head into parent",
            "folding element body into parent",
            "css property top has bad value: ==&gt;expression(alert(0), 0)");
    testMarkup(markup, expected, messages);
  }
  
  @Test
  public void testRewrite() throws Exception {
    String markup = "<script>var a=0;</script>";
    String expected =
        "caja___.start";

    List<String> messages = ImmutableList.of(
            "folding element html into parent",
            "folding element head into parent",
            "folding element body into parent");
    testMarkup(markup, expected, messages);
  }

  @Test
  public void testUrlRewrite() throws Exception {
    String uri = "http://www.example.com/";
    String unproxied = uri;
    String proxied = "http://shindig.com/gadgets/proxy?url=" + uri;
    
    expect(proxyUriManager.make(EasyMock.anyObject(List.class), EasyMock.isNull(Integer.class)))
        .andReturn(ImmutableList.<Uri>of(Uri.parse(proxied))).anyTimes();
    replay(proxyUriManager);

    // Uris that transistion the page
    assertUrlRewritten("a", "href", uri, unproxied);
    assertUrlRewritten("area", "href", uri, unproxied);
    
    // Uris that load media
    assertUrlRewritten("img", "src", uri, proxied);
    
    // Uris that have no effect on the document
    assertUrlRewritten("blockquote", "cite", uri, unproxied);
    assertUrlRewritten("q", "cite", uri, unproxied);
    assertUrlRewritten("del", "cite", uri, unproxied);
    assertUrlRewritten("ins", "cite", uri, unproxied);
  }
  
  private void testMarkup(String markup, String expected) throws GadgetException{
    testMarkup(markup, expected, null);
  }

  private void assertUrlRewritten(String tagName, String attr, String orig, String rewritten)
      throws Exception {
    String markUp = "<" + tagName + " " + attr + "=\"" + orig + "\">";
    String expected = attr + "=\"" + rewritten + "\"";
    testMarkup(markUp, expected);
  }
  
  private void testMarkup(String markup, String expected, List<String> msgs) throws GadgetException{
    Gadget gadget = makeGadget();
    for (GadgetHtmlParser parser : parsers) {
      MutableContent mc = new MutableContent(parser, markup);
      rewriter.rewrite(gadget, mc);

      String actual = mc.getContent();
      assertTrue(actual.contains(expected));

      if (msgs != null) {
        for (String msg : msgs) {
          System.out.println("Msg:" + msg);
          assertTrue(actual.contains(msg));
        }
      }
    }
  }

  private Gadget makeGadget() throws GadgetException {
    Gadget gadget = EasyMock.createNiceMock(Gadget.class);
    GadgetContext context = EasyMock.createNiceMock(GadgetContext.class);

    expect(context.getUrl()).andReturn(Uri.parse("http://example.com/gadget.xml")).anyTimes();
    expect(context.getContainer()).andReturn("cajaContainer").anyTimes();
    expect(context.getDebug()).andReturn(false).anyTimes();

    expect(gadget.getContext()).andReturn(context).anyTimes();
    expect(gadget.getAllFeatures()).andReturn(ImmutableList.of("caja")).anyTimes();
    expect(gadget.requiresCaja()).andReturn(true).anyTimes();

    replay(context, gadget);
    return gadget;
  }
}
