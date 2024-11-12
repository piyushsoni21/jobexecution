package com.jobexecution.service.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jobexecution.service.exception.dto.ErrorDto;
import com.jobexecution.service.exception.dto.ErrorsDto;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.jobexecution.service.util.Constant.JWT;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    private static final String RESTRICTED_URLS = "/api/v1/auth";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return path.startsWith(RESTRICTED_URLS);
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response,
                                    @NotNull FilterChain filterChain) throws ServletException, IOException {

        String jwt = null;
        final String userName;
        try{

            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (JWT.equals(cookie.getName())) {
                        jwt = cookie.getValue();
                        break;
                    }
                }
            }

            if (jwt == null) {
                final String authHeader = request.getHeader("Authorization");
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    throw new JwtException("JWT Token is missing or invalid");
                }
                jwt = authHeader.substring(7);
            }

            userName = jwtService.extractUserName(jwt);

            if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userName);
                if (jwtService.validateToken(jwt, userDetails)){
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        }
        catch (UsernameNotFoundException e){
            sendErrorResponse(response, HttpStatus.NOT_FOUND, e);
            return;
        }
        catch (JwtException | AuthenticationException e ){
            sendErrorResponse(response, HttpStatus.FORBIDDEN, e);
            return;
        }
        catch (Exception e){
            sendErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR, e);
            return;
        }
        filterChain.doFilter(request,response);
    }

    private void sendErrorResponse(HttpServletResponse response, HttpStatus httpStatus, Exception e) throws IOException {
        response.reset();
        response.setStatus(httpStatus.value());
        response.setContentType("application/json");

        ErrorsDto errorsDto = ErrorsDto.builder()
                        .error(ErrorDto.builder()
                                .reasonCode(String.valueOf(httpStatus.value()))
                                .description(httpStatus.getReasonPhrase())
                                .details(e.getMessage())
                                .build())
                        .build();

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(errorsDto);

        response.getWriter().write(jsonResponse);
    }
}
