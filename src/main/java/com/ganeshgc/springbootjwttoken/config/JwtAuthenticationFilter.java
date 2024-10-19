package com.ganeshgc.springbootjwttoken.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
       //extracting header from the request
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
      //===============================================================================================================
        // Checking the Authorization header in the HTTP request
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // If the Authorization header is missing (authHeader == null)
            // OR it doesn't start with "Bearer " (meaning no Bearer token is present)

            filterChain.doFilter(request, response); // Continue to the next filter in the filter chain
            return; // Exit the current method early
        }

        //===============================================================================================================
        //extracting the jwt from the header
        jwt = authHeader.substring(7);

        userEmail=jwtService.extractUsername(jwt);
        // just checking whether the user is already authenticated or not if already authenticated in previous request then no need to go and check in userdetail service
       // getAuthentication()==null this mean user is not authenticated yet so you have to go the userdetailservice to check
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Check if the user's email is not null and there's no existing authentication in the SecurityContext.
            // This means that the user is not yet authenticated in the current session.

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // Load the user's details from the database (or another user store) based on the email address.
            // 'userDetails' contains user-specific information like username, password, and authorities (roles).



//==========================================================================================================================================
// check the jwt still valid or not
            //function of the below code is to update springcontextholder for this request and future request for this session

            if(jwtService.isTokenValid(jwt, userDetails)) {
                // Validate the JWT to check if it's still valid for this user.
                // This ensures that the JWT hasn't expired and corresponds to the loaded user details.

                // if user and token are valid we create object of UsernamePasswordAuthenticationToken
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                //This part creates a new authentication object (authToken) with the user's details (from UserDetails), the credentials (set as null because JWT already proves the user’s identity), and their authorities (roles/permissions).
                // Create a new UsernamePasswordAuthenticationToken with the user's details and authorities (roles).
                // This token will be used to authenticate the user in the security context.
                // The second argument is 'null' because no credentials are being passed here (password is not required at this point).

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // Attach additional details to the authentication object, such as the current request (IP address, session info).
                // This helps to track where the authentication request is coming from.

                // update SecurityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authToken);
                // Set the authentication object (authToken) in the SecurityContext.
                // This means the user is now authenticated and their details are stored in the SecurityContext for future requests.
            }
        }

        //asking filter chain to do after filter at last( passing next filter to be executed)
filterChain.doFilter(request,response);

    }
}
