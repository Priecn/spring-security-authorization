package learn.security.authorization;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@SpringBootApplication
public class AuthorizationApplication {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }

}

@EnableWebSecurity
@Configuration
class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http.formLogin();

        http.authorizeRequests()
                .mvcMatchers("/root").hasAnyAuthority("ADMIN")
                .mvcMatchers(HttpMethod.GET, "/a").access("hasAuthority('ADMIN')")
                .mvcMatchers(HttpMethod.POST, "/b").access("@authz.check(request, principal)")
                .mvcMatchers("/user/{name}").access("#name == principal?.username")
                .anyRequest().permitAll();
    }
}

@Service("authz")
class AuthService {
    private final Logger log = LoggerFactory.getLogger(this.getClass());
    public boolean check(HttpServletRequest request, CustomUser principal) {
        log.info("checking incoming request "+ request.getRequestURI()+" for principal " + principal.getUsername());
        return true;
    }
}

@RestController
class RootRestController {

    @GetMapping("/root")
    public String root() {
        return "root";
    }
}

@RestController
class LetterRestController {

    @GetMapping("/a")
    String a() {
        return "a";
    }

    @PostMapping("/b")
    String b() {
        return "b";
    }

    @GetMapping("/c")
    String c() {
        return "c";
    }
}

@RestController
class UserRestController {
    @GetMapping("/user/{name}")
    public String getUserByName(@PathVariable String name) {
        return "user: " + name;
    }

}

@Service
class CustomUserDetailsService implements UserDetailsService {


    private final Map<String, UserDetails> users = new HashMap<>();

    public CustomUserDetailsService() {
        this.users.put("jlong", new CustomUser("jlong", "password", true, "USER"));
        this.users.put("rwinch", new CustomUser("rwinch", "password", true, "USER", "ADMIN"));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(this.users.containsKey(username))
            return this.users.get(username);
        throw new UsernameNotFoundException("couldn't find user "+ username);
    }
}


class CustomUser implements UserDetails {

    private Set<GrantedAuthority> authorities = new HashSet<>();
    private String username, password;
    private boolean active;

    public CustomUser(String username, String password, boolean active, String ...authorities) {
        this.authorities
                .addAll(Arrays.stream(authorities).map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toSet()));
        this.username = username;
        this.password = password;
        this.active = active;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.active;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.active;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.active;
    }

    @Override
    public boolean isEnabled() {
        return this.active;
    }
}
