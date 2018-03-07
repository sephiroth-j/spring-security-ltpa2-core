# Spring Security LTPA2
Add Spring Security support for user pre-authentication using IBM Lightweight Third Party Authentication (LTPA) v2. LTPA2 tokens can be created as well.

# Usage
Checkout my [sample project](https://github.com/sephiroth-j/spring-security-ltpa2-sample) for a complete example.

## pom.xml
Add it as an dependency together with you Spring Security dependencies.

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
	
## Web Security Configuration
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
