package jp.eisbahn.oauth2.server.data;

import jp.eisbahn.oauth2.server.async.Handler;
import jp.eisbahn.oauth2.server.models.AccessToken;
import jp.eisbahn.oauth2.server.models.AuthInfo;
import jp.eisbahn.oauth2.server.models.Request;

public abstract class DataHandlerSync extends DataHandler {

	public DataHandlerSync(Request request) {
		super(request);
	}

	@Override
	public void validateClient(String clientId, String clientSecret,
			String grantType, Handler<Boolean> handler) {
		handler.handle(validateClient(clientId, clientSecret, grantType));
	}

	public abstract boolean validateClient(String clientId, String clientSecret,
			String grantType);

	@Override
	public void getUserId(String username, String password,
			Handler<String> handler) {
		handler.handle(getUserId(username, password));

	}

	public abstract String getUserId(String username, String password);

	@Override
	public void createOrUpdateAuthInfo(String clientId, String userId,
			String scope, Handler<AuthInfo> handler) {
		handler.handle(createOrUpdateAuthInfo(clientId, userId, scope));
	}

	public abstract AuthInfo createOrUpdateAuthInfo(String clientId, String userId, String scope);

	@Override
	public void createOrUpdateAccessToken(AuthInfo authInfo,
			Handler<AccessToken> handler) {
		handler.handle(createOrUpdateAccessToken(authInfo));
	}

	public abstract AccessToken createOrUpdateAccessToken(AuthInfo authInfo);

	@Override
	public void getAuthInfoByCode(String code, Handler<AuthInfo> handler) {
		handler.handle(getAuthInfoByCode(code));
	}

	public abstract AuthInfo getAuthInfoByCode(String code);

	@Override
	public void getAuthInfoByRefreshToken(String refreshToken,
			Handler<AuthInfo> handler) {
		handler.handle(getAuthInfoByRefreshToken(refreshToken));
	}

	public abstract AuthInfo getAuthInfoByRefreshToken(String refreshToken);

	@Override
	public void getClientUserId(String clientId, String clientSecret,
			Handler<String> handler) {
		handler.handle(getClientUserId(clientId, clientSecret));
	}

	public abstract String getClientUserId(String clientId, String clientSecret);

	@Override
	public void validateClientById(String clientId, Handler<Boolean> handler) {
		handler.handle(validateClientById(clientId));
	}

	public abstract boolean validateClientById(String clientId);

	@Override
	public void validateUserById(String userId, Handler<Boolean> handler) {
		handler.handle(validateUserById(userId));
	}

	public abstract boolean validateUserById(String userId);

	@Override
	public void getAccessToken(String token, Handler<AccessToken> handler) {
		handler.handle(getAccessToken(token));
	}

	public abstract AccessToken getAccessToken(String token);

	@Override
	public void getAuthInfoById(String id, Handler<AuthInfo> handler) {
		handler.handle(getAuthInfoById(id));
	}

	public abstract AuthInfo getAuthInfoById(String id);

}
