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
import jp.eisbahn.oauth2.server.mock.MockDataHandler;
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
		expect(request.getHeader("Authorization")).andReturn("Bearer null").times(2);
		DataHandlerSync DataHandlerSync = new MockDataHandler(request);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSyncFactory);
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
		expect(request.getHeader("Authorization")).andReturn("Bearer expiredToken").times(2);
		DataHandlerSync DataHandlerSync = new MockDataHandler(request);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSyncFactory);
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
		expect(request.getHeader("Authorization")).andReturn("Bearer authNull").times(2);
		DataHandlerSync DataHandlerSync = new MockDataHandler(request);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSyncFactory);
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
		expect(request.getHeader("Authorization")).andReturn("Bearer accessToken1clientFailed").times(2);
		DataHandlerSync DataHandlerSync = new MockDataHandler(request);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSyncFactory);
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
		expect(request.getHeader("Authorization")).andReturn("Bearer userFailed").times(2);
		DataHandlerSync DataHandlerSync = new MockDataHandler(request);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSyncFactory);
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
		DataHandlerSync DataHandlerSync = new MockDataHandler(request);
		DataHandlerFactory DataHandlerSyncFactory = createMock(DataHandlerFactory.class);
		expect(DataHandlerSyncFactory.create(request)).andReturn(DataHandlerSync);
		replay(request, DataHandlerSyncFactory);
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
