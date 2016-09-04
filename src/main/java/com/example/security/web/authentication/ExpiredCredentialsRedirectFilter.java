package com.example.security.web.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

public class ExpiredCredentialsRedirectFilter extends GenericFilterBean {

	private final String expiredCredentialsUrl;

	private final RequestMatcher requestMatcher;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public ExpiredCredentialsRedirectFilter(String expiredCredentialsUrl) {
		Assert.hasLength(expiredCredentialsUrl, "expiredCredentialsUrl must not be empty");
		Assert.isTrue(UrlUtils.isValidRedirectUrl(expiredCredentialsUrl),
				expiredCredentialsUrl + " is not a valid redirect URL");
		this.expiredCredentialsUrl = expiredCredentialsUrl;
		this.requestMatcher = new RegexRequestMatcher(expiredCredentialsUrl.replace("?", "\\?"), null);
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (!this.requestMatcher.matches(request)) {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication != null && credentialsExpired(authentication)) {
				this.redirectStrategy.sendRedirect(request, response, this.expiredCredentialsUrl);
			}
		}

		chain.doFilter(request, response);
	}

	protected boolean credentialsExpired(Authentication authentication) {
		if (authentication.getPrincipal() instanceof UserDetails) {
			UserDetails userDetails = (UserDetails) authentication.getPrincipal();
			return !userDetails.isCredentialsNonExpired();
		}
		return false;
	}

}
