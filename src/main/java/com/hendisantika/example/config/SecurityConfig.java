package com.hendisantika.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    // Inject UserDetailsService through constructor
    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/", "/public/**").permitAll()     // Use requestMatchers() instead of antMatchers()
                                .requestMatchers("/users/**").hasAuthority("ADMIN")
                                .anyRequest().fullyAuthenticated()
                )
                .formLogin(form ->
                        form.loginPage("/login")
                                .failureUrl("/login?error")
                                .usernameParameter("email")
                                .permitAll()
                )
                .logout(logout ->
                        logout.logoutUrl("/logout")
                                .deleteCookies("remember-me")
                                .logoutSuccessUrl("/")
                                .permitAll()
                )
                // Updated rememberMe() configuration for Spring Security 6.1+
                .rememberMe(rememberMe ->
                        rememberMe
                                .tokenRepository(inMemoryTokenRepository())  // Use in-memory token repository or a custom one
                                .key("uniqueAndSecretKey")                    // Set a custom key for the token repository
                                .tokenValiditySeconds(86400)                 // Set validity (e.g., 1 day)
                );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // PersistentTokenRepository for remember-me persistence (optional, use if needed)
    @Bean
    public PersistentTokenRepository inMemoryTokenRepository() {
        return new InMemoryTokenRepositoryImpl();
    }
}
