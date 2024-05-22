package com.example.mycryptinbio;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MycryptinbioApplication {

	public static void main(String[] args) {
		SpringApplication.run(MycryptinbioApplication.class, args);
		System.out.println("Server live: listening on http://localhost:8080/crypto");
	}

}
