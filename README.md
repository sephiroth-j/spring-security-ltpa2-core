# Spring Security LTPA2

[![Build Status](https://app.travis-ci.com/sephiroth-j/spring-security-ltpa2-core.svg?branch=master)](https://app.travis-ci.com/github/sephiroth-j/spring-security-ltpa2-core) [![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=de.sephiroth-j%3Aspring-security-ltpa2&metric=alert_status)](https://sonarcloud.io/dashboard?id=de.sephiroth-j%3Aspring-security-ltpa2) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Add Spring Security support for user pre-authentication using IBM Lightweight Third Party Authentication (LTPA) v2. LTPA2 tokens can be created as well to consume other LTPA2-protected services or act as an LTPA2 authentication service.

Tokens are either taken from an HTTP header (default `Authorization` with prefix `LtpaToken2`) or a cookie (default `LtpaToken2`). Both names can be configured as needed, as well as the value prefix.

**Examples**

```bash
# default header and value prefix
curl -i -H "Authorization: LtpaToken2 <token-value>" http://localhost:8080/hello
# custom header name without value prefix
curl -i -H "My-Auth-Header: <token-value>" http://localhost:8080/hello
# default cookie
curl -i -b "LtpaToken2=<token-value>" http://localhost:8080/hello
# custom cookie name
curl -i -b "My-Auth-Cookie=<token-value>" http://localhost:8080/hello
```

An absolute minimum requirement for configuration are the shared secret key needed for decrypting the token and, in order to verify its signature, the public key from the identity provider that created the token.

## Usage
Checkout the [servlet sample project](https://github.com/sephiroth-j/spring-security-ltpa2-sample) or [reactive sample project](https://github.com/sephiroth-j/spring-security-ltpa2-reactive-sample) for a complete example.

### pom.xml
Add the library as an dependency together with your Spring Security dependencies.

```xml
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
		<version>[1.0.0,)</version>
	</dependency>
</dependencies>

<repositories>
	<repository>
		<id>mrepo.sephiroth-j.de</id>
		<url>http://mrepo.sephiroth-j.de/</url>
	</repository>
</repositories>
```

### Security Configuration for Web Servlet
Add the `Ltpa2Filter` using `Ltpa2Configurer`. It needs a `SecretKey` instance of the shared key that is used for the symmetric encryption of the LTPA2 token. In order to verify the provided token, it also needs the `PublicKey` from the identity provider (for example IBM Secure Gateway / DataPower) that sends the LTPA2 token.

As the user is pre-authenticated, **an instance of `UserDetailsService` is required** to setup the security context and populate it with the granted roles for the authenticated user. In this example we will simply use `InMemoryAuthentication` with a hard-coded list of users and their roles.

```java
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
```

### Security Configuration for Web Reactive
Add an `AuthenticationWebFilter` using `Ltpa2AuthManager` and the `Ltpa2AuthConverter`. The `Ltpa2AuthConverter` needs a `SecretKey` instance of the shared key that is used for the symmetric encryption of the LTPA2 token. In order to verify the provided token, it also needs the `PublicKey` from the identity provider (for example IBM Secure Gateway / DataPower) that sends the LTPA2 token.

As the user is pre-authenticated, **an instance of `ReactiveUserDetailsService` is required** to setup the security context and populate it with the granted roles for the authenticated user. In this example we will simply use `MapReactiveUserDetailsService` with a hard-coded list of users and their roles.

```java
@Configuration
@EnableWebFluxSecurity
public class WebSecurityConfig
{

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(final ServerHttpSecurity http, final ReactiveUserDetailsService userDetailsService, AuthenticationWebFilter ltpa2AuthenticationWebFilter)
	{
		http
			.httpBasic().disable()
			.authorizeExchange()
			// all other require any authentication
			.anyExchange().authenticated()
			.and()
			// apply ltpa2 authentication filter
			.addFilterAt(ltpa2AuthenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION);
		return http.build();
	}

	@Bean
	AuthenticationWebFilter x509AuthenticationWebFilter(ReactiveUserDetailsService userDetailsService) throws GeneralSecurityException
	{
		final Ltpa2AuthConverter converter = new Ltpa2AuthConverter();
		converter.setSharedKey(sharedKey());
		converter.setSignerKey(signerKey());

		final AuthenticationWebFilter webfilter = new AuthenticationWebFilter(new Ltpa2AuthManager(userDetailsService));
		webfilter.setServerAuthenticationConverter(converter);
		return webfilter;
	}

	@Bean
	public ReactiveUserDetailsService userDetailsService()
	{
		return new MapReactiveUserDetailsService(User.withUsername("user").password("password").roles("USER").build());
	}
}
```

## Project info and Javadoc
[Maven Site](http://www.sephiroth-j.de/java/spring-security-ltpa2/)

[Javadoc](http://www.sephiroth-j.de/java/spring-security-ltpa2/apidocs/)
