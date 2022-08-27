# Spring Security LTPA2 - Changelog

## Unreleased
### ⚠ Breaking
### ⭐ New Features
### 🐞 Bugs Fixed

## v1.1.0 - 2022-??-??
### ⚠ Breaking
### ⭐ New Features
- Allow to change the default behaviour when an authentication failure occurs (Web Servlet only) (fixes [#3](https://github.com/sephiroth-j/spring-security-ltpa2-core/issues/3))
- `Ltpa2Configurer` will now also find its `UserDetailsService` if it was provided as a bean

### 🐞 Bugs Fixed
- do not expose reason of the `AuthenticationException` as response message when authentication failed (Web Servlet only)

##  v1.0.0 - 2020-01-05
### ⚠ Breaking
- Spring Security 5.1 is at least required
- `Ltpa2Filter` will now return `FORBIDDEN` instead of `UNAUTHORIZED` when there was a problem with the token or the user was not found.
This corresponds more to the HTTP specification and matches the default behavior when no token was given at all.
- The dependencies on Spring Security and `slf4j-api` are no longer optional - only `reactor-core` is optional as it is only required for the reactive stack.

### ⭐ New Features
- Support the Reactive Stack with `Ltpa2AuthConverter` and `Ltpa2AuthManager`
check the [README](README.md) for the details
- Emit a warning when `allowExpiredToken` is enabled.

### 🐞 Bugs Fixed

##  v0.2.3 - 2019-05-05
### ⚠ Breaking
### ⭐ New Features
- **made most of the methods in `Ltpa2Utils` public**

### 🐞 Bugs Fixed
- fix: `Ltpa2Configurer` did not call `afterPropertiesSet` on the `Ltpa2Filter` instance after all properties where set which could lead to runtime errors
- other smaller fixes and increased test coverage

##  v0.2.2 - 2018-08-09
### ⚠ Breaking
### ⭐ New Features
- replaced `lombok.NonNull` with `org.springframework.lang.NonNull`

### 🐞 Bugs Fixed
- ensure "expire" and "user" attributes are not empty when set

##  v0.2.1 - 2018-08-09
### ⚠ Breaking
### ⭐ New Features
### 🐞 Bugs Fixed
- This release fixes an issue with different timezones when converting the expire attribute from unix timestamp to `LocalDateTime` and back.

##  v0.2.0 - 2018-03-11
### ⚠ Breaking
### ⭐ New Features
- allow custom header name
- update examples / usage page

### 🐞 Bugs Fixed
-  do not assume a fixed length for the private exponent and read its length from the private-exponent-length-field
- `afterPropertiesSet()` did not allow an empty value for `headerValueIdentifier` although it is allowed

##  v0.1.0 - 2018-03-07
initial release
