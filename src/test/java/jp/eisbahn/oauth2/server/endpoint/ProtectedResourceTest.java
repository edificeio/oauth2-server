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

package jp.eisbahn.oauth2.server.endpoint;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Calendar;
import java.util.Date;

import jp.eisbahn.oauth2.server.async.Handler;
import jp.eisbahn.oauth2.server.exceptions.Try;
import org.junit.Test;

import jp.eisbahn.oauth2.server.data.DataHandlerSync;
import jp.eisbahn.oauth2.server.data.DataHandlerFactory;
import jp.eisbahn.oauth2.server.endpoint.ProtectedResource.Response;
import jp.eisbahn.oauth2.server.exceptions.OAuthError;
import jp.eisbahn.oauth2.server.fetcher.accesstoken.AccessTokenFetcher;
import jp.eisbahn.oauth2.server.fetcher.accesstoken.AccessTokenFetcherProvider;
import jp.eisbahn.oauth2.server.fetcher.accesstoken.impl.AuthHeader;
import jp.eisbahn.oauth2.server.models.AccessToken;
import jp.eisbahn.oauth2.server.models.AuthInfo;
import jp.eisbahn.oauth2.server.models.Request;

public class ProtectedResourceTest {

	@Test
	public void testHandleRequestAccessTokenFetcherNotFound() throws Exception {
		final Request request = createMock(Request.class);
		replay(request);
		ProtectedResource target = new ProtectedResource();
		AccessTokenFetcherProvider accessTokenFetcherProvider = new AccessTokenFetcherProvider();
		accessTokenFetcherProvider.setAccessTokenFetchers(new AccessTokenFetcher[]{});
		target.setAccessTokenFetcherProvider(accessTokenFetcherProvider);
		target.handleRequest(request, new Handler<Try<OAuthError, Response>>() {
			@Override
			public void handle(Try<OAuthError, Response> event) {
				try {
					event.get();
					fail("OAuthError not occurred.");
				} catch (OAuthError e) {
					assertTrue(e instanceof OAuthError.InvalidRequest);
				}
				verify(request);
			}
		});

	}
	
	@Test
	public void testHandleRequestAccessTokenNotFound() throws Exception {
		final Request request = createMock(Request.class);
		expect(request.getHeader("Authorization")).andReturn("Bearer accessToken1").times(2);
		DataHandlerSync DataHandlerSync = createMock(DataHandlerSync.class);
		expect(DataHandlerSync.getAccessToken("accessToken1")).andReturn(null);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSync, DataHandlerSyncFactory);
		ProtectedResource target = new ProtectedResource();
		AccessTokenFetcherProvider accessTokenFetcherProvider = new AccessTokenFetcherProvider();
		accessTokenFetcherProvider.setAccessTokenFetchers(new AccessTokenFetcher[]{
				new AuthHeader()
		});
		target.setAccessTokenFetcherProvider(accessTokenFetcherProvider);
		target.setDataHandlerFactory(DataHandlerSyncFactory);
		target.handleRequest(request, new Handler<Try<OAuthError, Response>>() {
			@Override
			public void handle(Try<OAuthError, Response> event) {
				try {
					event.get();
					fail("OAuthError not occurred.");
				} catch (OAuthError e) {
					assertTrue(e instanceof OAuthError.InvalidToken);
				}
				verify(request);
			}
		});
	}
	
	private Date createDate(int daysAgo) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(new Date());
		cal.add(Calendar.DATE, daysAgo);
		return cal.getTime();
	}
	
	@Test
	public void testHandleRequestAccessTokenExpired() throws Exception {
		final Request request = createMock(Request.class);
		expect(request.getHeader("Authorization")).andReturn("Bearer accessToken1").times(2);
		AccessToken accessToken = new AccessToken();
		accessToken.setCreatedOn(createDate(-1));
		accessToken.setExpiresIn(0);
		DataHandlerSync DataHandlerSync = createMock(DataHandlerSync.class);
		expect(DataHandlerSync.getAccessToken("accessToken1")).andReturn(accessToken);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSync, DataHandlerSyncFactory);
		ProtectedResource target = new ProtectedResource();
		AccessTokenFetcherProvider accessTokenFetcherProvider = new AccessTokenFetcherProvider();
		accessTokenFetcherProvider.setAccessTokenFetchers(new AccessTokenFetcher[]{
				new AuthHeader()
		});
		target.setAccessTokenFetcherProvider(accessTokenFetcherProvider);
		target.setDataHandlerFactory(DataHandlerSyncFactory);
		target.handleRequest(request, new Handler<Try<OAuthError, Response>>() {
			@Override
			public void handle(Try<OAuthError, Response> event) {
				try {
					event.get();
					fail("OAuthError not occurred.");
				} catch (OAuthError e) {
					assertTrue(e instanceof OAuthError.ExpiredToken);
				}
				verify(request);
			}
		});
	}

	@Test
	public void testHandleRequestAuthInfoNotFound() throws Exception {
		final Request request = createMock(Request.class);
		expect(request.getHeader("Authorization")).andReturn("Bearer accessToken1").times(2);
		AccessToken accessToken = new AccessToken();
		accessToken.setCreatedOn(createDate(0));
		accessToken.setExpiresIn(3600);
		accessToken.setAuthId("authId1");
		DataHandlerSync DataHandlerSync = createMock(DataHandlerSync.class);
		expect(DataHandlerSync.getAccessToken("accessToken1")).andReturn(accessToken);
		expect(DataHandlerSync.getAuthInfoById("authId1")).andReturn(null);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSync, DataHandlerSyncFactory);
		ProtectedResource target = new ProtectedResource();
		AccessTokenFetcherProvider accessTokenFetcherProvider = new AccessTokenFetcherProvider();
		accessTokenFetcherProvider.setAccessTokenFetchers(new AccessTokenFetcher[]{
				new AuthHeader()
		});
		target.setAccessTokenFetcherProvider(accessTokenFetcherProvider);
		target.setDataHandlerFactory(DataHandlerSyncFactory);
		target.handleRequest(request, new Handler<Try<OAuthError, Response>>() {
			@Override
			public void handle(Try<OAuthError, Response> event) {
				try {
					event.get();
					fail("OAuthError not occurred.");
				} catch (OAuthError e) {
					assertTrue(e instanceof OAuthError.InvalidToken);
				}
				verify(request);
			}
		});
	}

	@Test
	public void testHandleRequestValidateClientFailed() throws Exception {
		final Request request = createMock(Request.class);
		expect(request.getHeader("Authorization")).andReturn("Bearer accessToken1").times(2);
		AccessToken accessToken = new AccessToken();
		accessToken.setCreatedOn(createDate(0));
		accessToken.setExpiresIn(3600);
		accessToken.setAuthId("authId1");
		DataHandlerSync DataHandlerSync = createMock(DataHandlerSync.class);
		expect(DataHandlerSync.getAccessToken("accessToken1")).andReturn(accessToken);
		AuthInfo authInfo = new AuthInfo();
		authInfo.setClientId("clientId1");
		expect(DataHandlerSync.getAuthInfoById("authId1")).andReturn(authInfo);
		expect(DataHandlerSync.validateClientById("clientId1")).andReturn(false);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSync, DataHandlerSyncFactory);
		ProtectedResource target = new ProtectedResource();
		AccessTokenFetcherProvider accessTokenFetcherProvider = new AccessTokenFetcherProvider();
		accessTokenFetcherProvider.setAccessTokenFetchers(new AccessTokenFetcher[]{
				new AuthHeader()
		});
		target.setAccessTokenFetcherProvider(accessTokenFetcherProvider);
		target.setDataHandlerFactory(DataHandlerSyncFactory);
		target.handleRequest(request, new Handler<Try<OAuthError, Response>>() {
			@Override
			public void handle(Try<OAuthError, Response> event) {
				try {
					event.get();
					fail("OAuthError not occurred.");
				} catch (OAuthError e) {
					assertTrue(e instanceof OAuthError.InvalidToken);
				}
				verify(request);
			}
		});
	}

	@Test
	public void testHandleRequestValidateUserFailed() throws Exception {
		final Request request = createMock(Request.class);
		expect(request.getHeader("Authorization")).andReturn("Bearer accessToken1").times(2);
		AccessToken accessToken = new AccessToken();
		accessToken.setCreatedOn(createDate(0));
		accessToken.setExpiresIn(3600);
		accessToken.setAuthId("authId1");
		DataHandlerSync DataHandlerSync = createMock(DataHandlerSync.class);
		expect(DataHandlerSync.getAccessToken("accessToken1")).andReturn(accessToken);
		AuthInfo authInfo = new AuthInfo();
		authInfo.setClientId("clientId1");
		authInfo.setUserId("userId1");
		expect(DataHandlerSync.getAuthInfoById("authId1")).andReturn(authInfo);
		expect(DataHandlerSync.validateClientById("clientId1")).andReturn(true);
		expect(DataHandlerSync.validateUserById("userId1")).andReturn(false);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSync, DataHandlerSyncFactory);
		ProtectedResource target = new ProtectedResource();
		AccessTokenFetcherProvider accessTokenFetcherProvider = new AccessTokenFetcherProvider();
		accessTokenFetcherProvider.setAccessTokenFetchers(new AccessTokenFetcher[]{
				new AuthHeader()
		});
		target.setAccessTokenFetcherProvider(accessTokenFetcherProvider);
		target.setDataHandlerFactory(DataHandlerSyncFactory);
		target.handleRequest(request, new Handler<Try<OAuthError, Response>>() {
			@Override
			public void handle(Try<OAuthError, Response> event) {
				try {
					event.get();
					fail("OAuthError not occurred.");
				} catch (OAuthError e) {
					assertTrue(e instanceof OAuthError.InvalidToken);
				}
				verify(request);
			}
		});
	}

	@Test
	public void testHandleRequestSuccess() throws Exception {
		final Request request = createMock(Request.class);
		expect(request.getHeader("Authorization")).andReturn("Bearer accessToken1").times(2);
		AccessToken accessToken = new AccessToken();
		accessToken.setCreatedOn(createDate(0));
		accessToken.setExpiresIn(3600);
		accessToken.setAuthId("authId1");
		DataHandlerSync DataHandlerSync = createMock(DataHandlerSync.class);
		expect(DataHandlerSync.getAccessToken("accessToken1")).andReturn(accessToken);
		AuthInfo authInfo = new AuthInfo();
		authInfo.setClientId("clientId1");
		authInfo.setUserId("userId1");
		authInfo.setScope("scope1");
		expect(DataHandlerSync.getAuthInfoById("authId1")).andReturn(authInfo);
		expect(DataHandlerSync.validateClientById("clientId1")).andReturn(true);
		expect(DataHandlerSync.validateUserById("userId1")).andReturn(true);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSync, DataHandlerSyncFactory);
		ProtectedResource target = new ProtectedResource();
		AccessTokenFetcherProvider accessTokenFetcherProvider = new AccessTokenFetcherProvider();
		accessTokenFetcherProvider.setAccessTokenFetchers(new AccessTokenFetcher[]{
				new AuthHeader()
		});
		target.setAccessTokenFetcherProvider(accessTokenFetcherProvider);
		target.setDataHandlerFactory(DataHandlerSyncFactory);
		target.handleRequest(request, new Handler<Try<OAuthError, Response>>() {
			@Override
			public void handle(Try<OAuthError, Response> event) {
				try {
					Response response = event.get();
					assertEquals("userId1", response.getRemoteUser());
					assertEquals("clientId1", response.getClientId());
					assertEquals("scope1", response.getScope());
				} catch (OAuthError oAuthError) {
					fail("OAuthError occurred.");
				}
				verify(request);
			}
		});

	}

}
