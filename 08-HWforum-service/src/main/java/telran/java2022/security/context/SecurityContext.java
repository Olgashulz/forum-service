package telran.java2022.security.context;

public interface SecurityContext {
	User addUser(User user);

	User RemoveUser(String userName);

	User getUser(String userName);

}
