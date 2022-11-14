package telran.java2022.security.service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import telran.java2022.accounting.model.UserAccount;

@Service
public class SessionServiceImpl implements SessionService {
	Map<String, UserAccount> users = new ConcurrentHashMap<>();

	@Override
	public UserAccount addUser(String sessoinId, UserAccount userAccount) {
		return users.put(sessoinId, userAccount);
	}

	@Override
	public UserAccount getUser(String sessionId) {
		return users.get(sessionId);
	}

	@Override
	public UserAccount remove(String sessonId) {
		return users.remove(sessonId);
	}

}
