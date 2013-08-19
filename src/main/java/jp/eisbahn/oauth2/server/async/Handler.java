package jp.eisbahn.oauth2.server.async;

public interface Handler<T> {

	void handle(T event);

}
