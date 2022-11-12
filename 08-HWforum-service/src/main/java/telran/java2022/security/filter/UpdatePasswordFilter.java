package telran.java2022.security.filter;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;

@Component
@RequiredArgsConstructor
@Order(40)
public class UpdatePasswordFilter implements Filter {

	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			UserAccount userAccount = userAccountRepository
					.findById(request.getUserPrincipal().getName()).get();

			String token = request.getHeader("Authorization");
			String[] basicAuth = token.split(" ");
			String decode = new String(Base64.getDecoder().decode(basicAuth[1]));
			String[] credentials = decode.split(":");
			if(!BCrypt.checkpw(credentials[1], userAccount.getPassword())) {
				response.sendError(401, "login or password is invalid");
				return;
			}
			
			
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String servletPath) {
		return ("PUT".equalsIgnoreCase(method) && servletPath.matches("/account/password"));
	}
}
