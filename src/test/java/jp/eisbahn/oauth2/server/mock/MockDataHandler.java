package jp.eisbahn.oauth2.server.mock;

import jp.eisbahn.oauth2.server.async.Handler;
import jp.eisbahn.oauth2.server.data.DataHandlerSync;
import jp.eisbahn.oauth2.server.exceptions.Try;
import jp.eisbahn.oauth2.server.exceptions.OAuthError;
import jp.eisbahn.oauth2.server.exceptions.OAuthError.AccessDenied;
import jp.eisbahn.oauth2.server.models.AccessToken;
import jp.eisbahn.oauth2.server.models.AuthInfo;
import jp.eisbahn.oauth2.server.models.Request;
import jp.eisbahn.oauth2.server.models.UserData;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class MockDataHandler extends DataHandlerSync {

	public MockDataHandler(Request request) {
		super(request);
	}

	@Override
	public boolean validateClient(String clientId, String clientSecret,
			String grantType) {
		return !(clientId.contains("false") ||
				clientSecret.contains("false") || grantType.contains("false"));
	}

	@Override
	public Try<AccessDenied, String> getUserId(String username, String password) {
		if (username == null || password == null || username.contains("userNotFound")) {
			return new Try<AccessDenied, String>(new AccessDenied("user.not.found"));
		}
		return new Try<AccessDenied, String>(username);
	}

	@Override
	public Try<OAuthError, UserData> getUserIdByAssertion(String assertion) {
		return null;
	}

	@Override
	public Try<AccessDenied, UserData> getUserIdByCustomToken(String customToken) {
		return null;
	}

	@Override
	public AuthInfo createOrUpdateAuthInfo(String clientId, String userId,
			String scope) {
		if ("authInfoNotFound".equals(clientId) || "authInfoNotFound".equals(userId))
			return null;
		AuthInfo authInfo = new AuthInfo();
		if ("clientFailed".equals(userId)) {
			authInfo.setClientId("");
		} else {
			authInfo.setClientId("clientId1");
		}
		authInfo.setRedirectUri("redirectUri1");
		authInfo.setRefreshToken("refreshToken1");
		authInfo.setScope("scope1");
		return authInfo;
	}

	@Override
	public AccessToken createOrUpdateAccessToken(AuthInfo authInfo) {
		AccessToken accessToken = new AccessToken();
		accessToken.setToken("accessToken1");
		accessToken.setExpiresIn(900L);
		return accessToken;
	}

	@Override
	public AuthInfo getAuthInfoByCode(String code) {
		if (code == null || code.contains("null"))
			return null;
		AuthInfo authInfo = new AuthInfo();
		authInfo.setClientId(code.replaceAll("code", "clientId"));
		if (code.contains("missingRedirect")) {
			authInfo.setRedirectUri("");
		} else {
			authInfo.setRedirectUri(code.replaceAll("code", "redirectUri"));
		}
		authInfo.setRefreshToken("refreshToken1");
		authInfo.setScope("scope1");
		authInfo.setCode(code);
		return authInfo;
	}

	@Override
	public AuthInfo getAuthInfoByRefreshToken(String refreshToken) {
		if (refreshToken == null || refreshToken.contains("null"))
			return null;
		AuthInfo authInfo = new AuthInfo();
		if (refreshToken.contains("clientFailed")) {
			authInfo.setClientId("clientFailed");
		} else {
			authInfo.setClientId("clientId1");
		}
		authInfo.setRedirectUri("redirectUri1");
		authInfo.setRefreshToken(refreshToken);
		authInfo.setScope("scope1");
		authInfo.setCode("code1");
		return authInfo;
	}

	@Override
	public String getClientUserId(String clientId, String clientSecret) {
		if (clientId == null || clientSecret == null ||
				"null".equals(clientId) || "null".equals(clientSecret))
			return null;
		return "userId1";
	}

	@Override
	public AccessToken getAccessToken(String token) {
		if (token == null || "null".equals(token)) {
			return null;
		}
		AccessToken accessToken = new AccessToken();
		accessToken.setExpiresIn(3600);
		if (token.contains("clientFailed")) {
			accessToken.setAuthId("clientFailed");
		} else if (token.contains("authNull")) {
			accessToken.setAuthId("null");
		} else if (token.contains("userFailed")) {
			accessToken.setAuthId("userFailed");
		} else {
			accessToken.setAuthId("authId1");
		}
		if (token.contains("expiredToken")) {
			accessToken.setCreatedOn(createDate(-1));
		} else {
			accessToken.setCreatedOn(createDate(0));
		}
		return accessToken;
	}

	private Date createDate(int daysAgo) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(new Date());
		cal.add(Calendar.DATE, daysAgo);
		return cal.getTime();
	}

	@Override
	public AuthInfo getAuthInfoById(String id) {
		if (id == null || "null".equals(id))
			return null;
		AuthInfo authInfo = new AuthInfo();
		authInfo.setClientId(id.replaceAll("auth", "client"));
		if (id.contains("userFailed")) {
			authInfo.setUserId("userFailed");
		} else {
			authInfo.setUserId("userId1");
		}
		authInfo.setScope("scope1");
		return authInfo;
	}

	@Override
	public boolean validateClientById(String clientId) {
		return !"clientFailed".equals(clientId);
	}

	@Override
	public boolean validateUserById(String userId) {
		return !"userFailed".equals(userId);
	}

	@Override
	public void getUserIdByAssertionJwt(String clientId, String assertion, Handler<Try<OAuthError, UserData>> handler) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'getUserIdByAssertionJwt'");
	}

	public void getAuthorizationsBySessionId(String sessionId, Handler<List<AuthInfo>> handler) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'getAuthorizationsBySessionId'");
	}

	@Override
	public void getTokensByAuthId(String authId, Handler<List<AccessToken>> handler) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'getTokensByAuthId'");
	}

	@Override
	public void deleteTokensByAuthId(String authId) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'deleteTokensByAuthId'");
	}

}