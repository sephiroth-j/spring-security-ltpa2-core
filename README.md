# Spring Security LTPA2

[![Build Status](https://travis-ci.com/sephiroth-j/spring-security-ltpa2-sample.svg?branch=master)](https://travis-ci.com/sephiroth-j/spring-security-ltpa2-sample) [![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=sephiroth-j_spring-security-ltpa2-core&metric=alert_status)](https://sonarcloud.io/dashboard?id=sephiroth-j_spring-security-ltpa2-core)

Add Spring Security support for user pre-authentication using IBM Lightweight Third Party Authentication (LTPA) v2. LTPA2 tokens can be created as well.

Tokens are either taken from an HTTP header (default `Authorization` with prefix `LtpaToken2`) or a cookie (default `LtpaToken2`). Both names can be configured as needed, as well as the value prefix.

**Examples**

	# default header and value prefix
	curl -i -H "Authorization: LtpaToken2 <token-value>" http://localhost:8080/hello
	# custom header name without value prefix
	curl -i -H "My-Auth-Header: <token-value>" http://localhost:8080/hello
	# default cookie
	curl -i -b "LtpaToken2=<token-value>" http://localhost:8080/hello
	# custom cookie name
	curl -i -b "My-Auth-Cookie=<token-value>" http://localhost:8080/hello

An absolute minimum requirement for configuration are the shared secret key needed for decrypting the token and, in order to verify its signature, the public key from the identity provider that created the token.

## Usage
Checkout my [sample project](https://github.com/sephiroth-j/spring-security-ltpa2-sample) for a complete example.

### pom.xml
Add the library as an dependency together with your Spring Security dependencies.

	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-ldap</artifactId>
		</dependency>
		<dependency>
			<groupId>de.sephiroth-j</groupId>
			<artifactId>spring-security-ltpa2</artifactId>
			<version>[0.1.0,)</version>
		</dependency>
	</dependencies>

	<repositories>
		<repository>
			<id>mrepo.sephiroth-j.de</id>
			<url>http://mrepo.sephiroth-j.de/</url>
		</repository>
	</repositories>
	
### Web Security Configuration
Add the `Ltpa2Filter` using `Ltpa2Configurer`. It needs a `SecretKey` instance of the shared key that is used for the symmetric encryption of the LTPA2 token. In order to verify the provided token, it also needs the `PublicKey` from the identity provider (for example IBM Secure Gateway / DataPower) that sends the LTPA2 token.

As the user is pre-authenticated, **an instance of `UserDetailsService` is required** to setup the security context and populate it with the granted roles for the authenticated user. In this example we will simply use `InMemoryAuthentication` with a hard-coded list of users and their roles.

	@Configuration
	@EnableWebSecurity
	public class WebSecurityConfig extends WebSecurityConfigurerAdapter
	{

		@Override
		protected void configure(HttpSecurity http) throws Exception
		{
			http
				.authorizeRequests()
					.antMatchers("/", "/home").permitAll()
					.antMatchers("/hello").hasRole("USER")
					.and()
				// configure LTPA2 Support
				.apply(new Ltpa2Configurer())
					.sharedKey(sharedKey())
					.signerKey(signerKey())
				;
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception
		{
			auth.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER");
		}
	}
## Project info and Javadoc
[Maven Site](http://www.sephiroth-j.de/java/spring-security-ltpa2/)

[Javadoc](http://www.sephiroth-j.de/java/spring-security-ltpa2/apidocs/)
