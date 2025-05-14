
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Value("${bezkoder.app.jwtSecret}")
    private String jwtSecret;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
        throws ServletException, IOException {
            
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.replace("Bearer ", "");
            
            try {
                
                Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))  // Mismo método de lectura
                .build()
                .parseClaimsJws(token);


                String username = claims.getBody().getSubject();
                List<String> roles = claims.getBody().get("roles", List.class);
               
               
                List<GrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(auth);

            } 
            catch (JwtException e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Token inválido o expirado\"}");
                return;
            }
            catch (Exception e) {
                System.out.println(e.getMessage());
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}

