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


@Component
@RequiredArgsConstructor
@Order(30)
public class OwnerFilter implements Filter {
	final UserAccountRepository userAccountRepository;
//	final PostRepository postRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (checkEndPoint(request.getServletPath())) {
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			String path = request.getServletPath();
			String loginFromPath = path.substring(path.lastIndexOf('/') + 1);

			if ("PUT".equalsIgnoreCase(request.getMethod()) || "POST".equalsIgnoreCase(request.getMethod())) {
				if (!userAccount.getLogin().equals(loginFromPath))  {
					response.sendError(403);
					return;
				}
			}

			if ("DELETE".equalsIgnoreCase(request.getMethod())) {
				if (!userAccount.getRoles().contains("Administrator".toUpperCase())) {
					if (!userAccount.getLogin().equals(loginFromPath)) {
						response.sendError(403);
						return;
					}
				}
			}

		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String servletPath) {
		return (servletPath.matches("/account/user/\\w+") 
				|| servletPath.matches("/forum/post/\\w+") 
				|| servletPath.matches("/forum/post/\\w+/comment/\\w+"));		
	}

}
