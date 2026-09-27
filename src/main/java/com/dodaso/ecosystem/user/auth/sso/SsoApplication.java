package com.dodaso.ecosystem.user.auth.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//@SpringBootApplication(scanBasePackages = {"com.dodaso.user.auth", "com.dodaso.ecosystem.auth.dto", "com.dodaso.ecosystem.auth.container"}, exclude = {
//		DataSourceAutoConfiguration.class,
//		HibernateJpaAutoConfiguration.class,
//		DataSourceTransactionManagerAutoConfiguration.class,
//		JpaRepositoriesAutoConfiguration.class
//})
//@EntityScan(basePackages = {
//		"com.dodaso.ecosystem.auth.dto",  // Only scan your packages, not the JAR's
//		"com.dodaso.ecosystem.auth.container"
//})
@SpringBootApplication(scanBasePackages={"com.dodaso.ecosystem"})
public class SsoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SsoApplication.class, args);
	}

}