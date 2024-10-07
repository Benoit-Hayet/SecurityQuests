package com.securityQuest.security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;

/* JwtAuthenticationFilter hérite de OncePerRequestFilter, ce qui signifie que ce filtre est exécuté une seule fois par requête.
doFilterInternal : Cette méthode est exécutée pour chaque requête interceptée.
Elle commence par récupérer l'en-tête Authorization de la requête.
Si cet en-tête est présent et commence par "Bearer ", le filtre extrait le JWT.
Le filtre utilise ensuite JwtService pour extraire l'email (ou tout autre identifiant) du token JWT.
Si l'utilisateur est trouvé et n'est pas déjà authentifié, les détails de l'utilisateur sont chargés via UserDetailsService.
Si le token est valide et non expiré, une authentification est créée et enregistrée dans le SecurityContextHolder,
ce qui permet à l'utilisateur d'être considéré comme authentifié pour cette requête.
Enfin, la requête est transmise au filtre suivant dans la chaîne.*/

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwt = authHeader.substring(7);
            String username = jwtService.extractClaims(jwt).getSubject();

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                if (jwtService.extractClaims(jwt).getExpiration().after(new Date())) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}