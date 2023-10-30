package com.personal.security.SecurityJwtToken;

import com.personal.security.SecurityJwtToken.repository.RoleRepository;
import com.personal.security.SecurityJwtToken.repository.UserRepository;
import com.personal.security.SecurityJwtToken.user.ApplicationUser;
import com.personal.security.SecurityJwtToken.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class SecurityJwtTokenApplication {

	public static void main(String[] args) { SpringApplication.run(SecurityJwtTokenApplication.class, args);}

	/*
	@Bean
	CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository,
						  PasswordEncoder passwordEncoder) {
		return args -> {

			if(roleRepository.findByAuthority("ADMIN").isPresent()){
				return;
			}

			Role adminRole = new Role();
			adminRole.setAuthority("ADMIN");

			Role userRole = new Role();
			userRole.setAuthority("USER");

			roleRepository.save(adminRole);
			roleRepository.save(userRole);
			Set<Role> roleSet = new HashSet<>();
			roleSet.add(adminRole);

			ApplicationUser admin = new ApplicationUser();
			admin.setFirstName("Gözde");
			admin.setLastName("Apak");
			admin.setEmail("dk@test.com");
			admin.setPassword(passwordEncoder.encode("hello"));
			admin.setAuthorities(roleSet);
			userRepository.save(admin);

		};

	 */
	}


