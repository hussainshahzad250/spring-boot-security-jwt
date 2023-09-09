package com.security;

import com.security.models.Role;
import com.security.enums.RoleType;
import com.security.models.User;
import com.security.repository.RoleRepository;
import com.security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class SpringBootSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootSecurityJwtApplication.class, args);
    }


    @Bean
    CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncode) {
        return args -> {
            if (roleRepository.findByName(RoleType.ROLE_ADMIN).isEmpty()) {
                Set<Role> adminRoles = new HashSet<>();
                adminRoles.add(roleRepository.save(new Role(RoleType.ROLE_ADMIN)));
                userRepository.save(new User("admin", "admin@gmail.com", passwordEncode.encode("admin"), adminRoles));
            }
            if (roleRepository.findByName(RoleType.ROLE_ACCOUNT).isEmpty()) {
                Set<Role> accountRoles = new HashSet<>();
                accountRoles.add(roleRepository.save(new Role(RoleType.ROLE_ACCOUNT)));
                userRepository.save(new User("account", "account@gmail.com", passwordEncode.encode("account"), accountRoles));
            }
            if (roleRepository.findByName(RoleType.ROLE_USER).isEmpty()) {
                Set<Role> userRoles = new HashSet<>();
                userRoles.add(roleRepository.save(new Role(RoleType.ROLE_USER)));
                userRepository.save(new User("user", "user@gmail.com", passwordEncode.encode("user"), userRoles));
            }
        };
    }
}
