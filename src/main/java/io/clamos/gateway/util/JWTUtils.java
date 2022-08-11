package io.clamos.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JWTUtils {

    public Claims parse(String token) {

        try {
            return Jwts.parser()
                    .setSigningKey("DTrix.Mobile PatrolCam")
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            log.error("JwtException", e);
        }

        return null;
    }

}
