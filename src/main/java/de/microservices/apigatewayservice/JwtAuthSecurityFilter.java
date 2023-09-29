package de.microservices.apigatewayservice;

import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.annotation.NonNull;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthSecurityFilter implements WebFilter {

    private final JwtService jwtService;

    @Autowired
    public JwtAuthSecurityFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @NonNull
    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
//        var header = exchange.getRequest().getHeaders().getFirst(headerName);
 //       var payloadOpt = jwsService.verify(header);
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }
        String jwt = authHeader.substring(7);

 //       if (payloadOpt.isPresent() && payloadOpt.get().available()) {
//            var payload = payloadOpt.get();
        if(jwtService.isJwtValid(jwt)){
            List<? extends GrantedAuthority> authorities = new ArrayList<>();
            if (jwtService.getRolesFromToken(jwt) != null && jwtService.getRolesFromToken(jwt).size() != 0) {
                List<String> roles = jwtService.getRolesFromToken(jwt);
                authorities=roles.stream()
                        .map(role -> new SimpleGrantedAuthority(Arrays.toString(role.getBytes())))
                        .collect(Collectors.toList());
            }
            var authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsernameFromToken(jwt),null,authorities);
            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        }
        return chain.filter(exchange);
    }



   /* @NotNull
    @Override
    public Mono<Void> filter(@NotNull ServerWebExchange exchange, @NotNull WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }
        String jwt = authHeader.substring(7);
        if(jwtService.isJwtValid(jwt)){
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(new UserDetails() {
                @Override
                public Collection<? extends GrantedAuthority> getAuthorities() {
                    return jwtService.getRolesFromToken(jwt).stream()
                            .map(role -> new SimpleGrantedAuthority(Arrays.toString(role.getBytes())))
                            .collect(Collectors.toList());
                }

                @Override
                public String getPassword() {
                    return null;
                }

                @Override
                public String getUsername() {
                    return jwtService.getUsernameFromToken(jwt);
                }

                @Override
                public boolean isAccountNonExpired() {
                    return false;
                }

                @Override
                public boolean isAccountNonLocked() {
                    return false;
                }

                @Override
                public boolean isCredentialsNonExpired() {
                    return false;
                }

                @Override
                public boolean isEnabled() {
                    return false;
                }
            },null);


            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authenticationToken));


        }


        return chain.filter(exchange);
    }
*/


}
