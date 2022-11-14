package telran.java2022.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;
import telran.java2022.security.context.SecurityContext;
import telran.java2022.security.context.User;

@Component
@RequiredArgsConstructor
@Order(40)
public class ModeratorFilter implements Filter {
	final SecurityContext context;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (checkEndPoint(request.getServletPath())) {
			User userAccount = context.getUser(request.getUserPrincipal().getName());
			String path = request.getServletPath();
			String loginFromPath = path.substring(path.lastIndexOf('/') + 1);

			if ("DELETE".equalsIgnoreCase(request.getMethod())) {
				if (!userAccount.getRoles().contains("Administrator".toUpperCase())) {
					if (!userAccount.getUserName().equals(loginFromPath)) {
						response.sendError(403);
						return;
					}
				}
			}

		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String servletPath) {
		return (servletPath.matches("/account/user/\\w+"));
	}

}
