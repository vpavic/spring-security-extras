package com.example.security.web.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
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
import org.springframework.web.filter.OncePerRequestFilter;

public class ExpiredCredentialsRedirectFilter extends OncePerRequestFilter {

	public static final String SAVED_URL_ATTRIBUTE = ExpiredCredentialsRedirectFilter.class.getName() + ".SAVED_URL";

	private final String expiredCredentialsUrl;

	private final RequestMatcher requestMatcher;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private boolean useForward;

	public ExpiredCredentialsRedirectFilter(String expiredCredentialsUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(expiredCredentialsUrl),
				expiredCredentialsUrl + " is not a valid redirect URL");
		this.expiredCredentialsUrl = expiredCredentialsUrl;
		this.requestMatcher = new RegexRequestMatcher(expiredCredentialsUrl.replace("?", "\\?"), null);
	}

	public ExpiredCredentialsRedirectFilter(String expiredCredentialsUrl, boolean useForward) {
		this(expiredCredentialsUrl);
		this.useForward = useForward;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		if (!this.requestMatcher.matches(request)) {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication != null && credentialsExpired(authentication)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) throws IOException, ServletException {
		request.getSession().setAttribute(SAVED_URL_ATTRIBUTE, UrlUtils.buildFullRequestUrl(request));
		if (this.useForward) {
			request.getRequestDispatcher(this.expiredCredentialsUrl).forward(request, response);
		}
		else {
			this.redirectStrategy.sendRedirect(request, response, this.expiredCredentialsUrl);
			filterChain.doFilter(request, response);
		}
	}

	protected boolean credentialsExpired(Authentication authentication) {
		if (authentication.getPrincipal() instanceof UserDetails) {
			UserDetails userDetails = (UserDetails) authentication.getPrincipal();
			return !userDetails.isCredentialsNonExpired();
		}
		return false;
	}

}
