package com.securityQuest.security.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

   /* La méthode generateToken(UserDetails userDetails) génère un JWT pour un utilisateur authentifié.
    setSubject(userDetails.getUsername()) : Définit le sujet du token (souvent le nom d'utilisateur).
            claim("roles", userDetails.getAuthorities()) : Ajoute les rôles de l'utilisateur dans le token.
    setIssuedAt(new Date()) : Définit la date de création du token.
            setExpiration(new Date(System.currentTimeMillis() + jwtExpiration)) : Définit la date d'expiration du token.
    signWith(SignatureAlgorithm.HS256, secretKey) : Signe le token avec l'algorithme HS256 et la clé secrète.*/

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("roles", userDetails.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    /*La méthode 'extractClaims(String token)' extrait les informations intégrées dans le JWT.
setSigningKey(secretKey) : Configure la clé secrète utilisée pour vérifier la signature du token.
parseClaimsJws(token) : Analyse le token JWT pour extraire les informations.
getBody() : Récupère les revendications du corps du token.*/

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }

    /*La méthode validateJwtToken(String token) valide un JWT pour s'assurer qu'il est bien formé et non expiré.
Jwts.parserBuilder().setSigningKey(secretKey.getBytes()).build().parseClaimsJws(token);:
Tente de parser le token en utilisant la clé secrète. Si le token est valide, cette opération réussit.
Si une exception (JwtException ou IllegalArgumentException) est levée,
cela signifie que le token est invalide ou a expiré, et la méthode retourne false. Sinon, elle retourne true.*/

    public boolean validateJwtToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(secretKey.getBytes()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}