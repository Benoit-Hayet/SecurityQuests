package com.securityQuest.security.Service;

import com.securityQuest.security.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/*
Pour permettre au filtre d'authentification de charger les informations de l'utilisateur à partir de la base de données,
il est nécessaire de créer un service qui implémente l'interface UserDetailsService de Spring Security :
CustomUserDetailsService est un service qui implémente l'interface UserDetailsService.
LoadUserByUsername : Cette méthode est appelée par Spring Security pour charger un utilisateur à partir de la base de données
par son nom d'utilisateur (ou email dans ce cas).
Elle utilise UserRepository pour chercher l'utilisateur par email.
Si l'utilisateur est trouvé, ses détails sont retournés sous la forme d'un objet UserDetails.
Si l'utilisateur n'est pas trouvé, une exception UsernameNotFoundException est levée.
Intégration du filtre dans la configuration de sécurité*/

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;


    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé avec l'email : " + email));
    }
}