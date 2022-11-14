package telran.java2022.security.service;

import telran.java2022.accounting.model.UserAccount;

public interface SessionService {
UserAccount addUser(String sessoinId, UserAccount user);
UserAccount getUser(String sessonId);
UserAccount remove(String sessonId);
}
