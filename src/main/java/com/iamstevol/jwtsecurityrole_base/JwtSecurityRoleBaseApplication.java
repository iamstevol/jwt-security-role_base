package com.iamstevol.jwtsecurityrole_base;

import com.iamstevol.jwtsecurityrole_base.auth.AuthenticationService;
import com.iamstevol.jwtsecurityrole_base.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.iamstevol.jwtsecurityrole_base.user.Role.ADMIN;
import static com.iamstevol.jwtsecurityrole_base.user.Role.MANAGER;

@SpringBootApplication
public class JwtSecurityRoleBaseApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtSecurityRoleBaseApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(AuthenticationService service) {
        return args -> {
            var admin = RegisterRequest.builder()
                    .firstname("Admin")
                    .lastname("Admin")
                    .email("Admin@gmail.com")
                    .password("password")
                    .role(ADMIN)
                    .build();
            System.out.println("Admin Token: " + service.register(admin).getAccessToken());

            var manager = RegisterRequest.builder()
                    .firstname("Manager")
                    .lastname("Manager")
                    .email("manager@gmail.com")
                    .password("password")
                    .role(MANAGER)
                    .build();
            System.out.println("Manager Token: " + service.register(admin).getAccessToken());
        };
    }
}
