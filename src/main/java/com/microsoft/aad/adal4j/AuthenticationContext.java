/*******************************************************************************
 * Copyright © Microsoft Open Technologies, Inc.
 *
 * All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 ******************************************************************************/
package com.microsoft.aad.adal4j;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.JWTBearerGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

/**
 * The main class representing the authority issuing tokens for scopes. It
 * provides several ways to request access token, namely via Authorization Code,
 * Confidential Client and Client Certificate.
 */
public class AuthenticationContext {

	private final Logger log = LoggerFactory.getLogger(AuthenticationContext.class);

	private final AuthenticationAuthority authenticationAuthority;
	private String correlationId;
	private String authority;
	private final ExecutorService service;
	private final boolean validateAuthority;

	/**
	 * Constructor to create the context with the address of the authority.
	 *
	 * @param authority
	 *            URL of the authenticating authority
	 * @param validateAuthority
	 *            flag to enable/disable authority validation.
	 * @param service
	 *            ExecutorService to be used to execute the requests. Developer
	 *            is responsible for maintaining the lifetime of the
	 *            ExecutorService.
	 * @throws MalformedURLException
	 *             thrown if URL is invalid
	 */
	public AuthenticationContext(final String authority, final boolean validateAuthority, final ExecutorService service)
			throws MalformedURLException {

		if (StringHelper.isBlank(authority)) {
			throw new IllegalArgumentException("authority is null or empty");
		}

		if (service == null) {
			throw new IllegalArgumentException("service is null");
		}
		this.service = service;
		this.validateAuthority = validateAuthority;
		this.authority = this.canonicalizeUri(authority);

		authenticationAuthority = new AuthenticationAuthority(new URL(this.getAuthority()),
				this.shouldValidateAuthority());
	}

	private String canonicalizeUri(String authority) {
		if (!authority.endsWith("/")) {
			authority += "/";
		}
		return authority;
	}

	private Future<AuthenticationResult> acquireToken(final AdalAuthorizatonGrant authGrant,
			final ClientAuthentication clientAuth, final String policy, final AuthenticationCallback callback) {

		return service.submit(new Callable<AuthenticationResult>() {

			private AdalAuthorizatonGrant authGrant;
			private ClientAuthentication clientAuth;
			private ClientDataHttpHeaders headers;
			private String policy;

			@Override
			public AuthenticationResult call() throws Exception {
				AuthenticationResult result = null;
				try {
					result = acquireTokenCommon(this.authGrant, this.clientAuth, this.headers, policy);
					logResult(result, headers);
					if (callback != null) {
						callback.onSuccess(result);
					}
				} catch (final Exception ex) {
					log.error(LogHelper.createMessage("Request to acquire token failed.",
							this.headers.getHeaderCorrelationIdValue()), ex);
					if (callback != null) {
						callback.onFailure(ex);
					} else {
						throw ex;
					}
				}
				return result;
			}

			private Callable<AuthenticationResult> init(final AdalAuthorizatonGrant authGrant,
					final ClientAuthentication clientAuth, final ClientDataHttpHeaders headers, final String policy) {
				this.authGrant = authGrant;
				this.clientAuth = clientAuth;
				this.headers = headers;
				this.policy = policy;
				return this;
			}
		}.init(authGrant, clientAuth, new ClientDataHttpHeaders(this.getCorrelationId()), policy));
	}

	/**
	 * Acquires security token from the authority.
	 *
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param credential
	 *            The client assertion to use for token acquisition.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token and the Access Token's expiration time. Refresh Token
	 *         property will be null for this overload.
	 */
	public Future<AuthenticationResult> acquireToken(final String[] scope, final ClientAssertion credential,
			final AuthenticationCallback callback) {
		return this.acquireToken(scope, credential, (String) null, callback);
	}

	/**
	 * Acquires security token from the authority.
	 *
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param credential
	 *            The client assertion to use for token acquisition.
	 * @param policy
	 *            Client policy
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token and the Access Token's expiration time. Refresh Token
	 *         property will be null for this overload.
	 */
	public Future<AuthenticationResult> acquireToken(final String[] scope, final ClientAssertion credential,
			String policy, final AuthenticationCallback callback) {
		this.validateInput(scope, credential);
		final ClientAuthentication clientAuth = createClientAuthFromClientAssertion(credential);
		String[] decoratedScope = this.decorateScope(scope, credential.getClientId());
		final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(new ClientCredentialsGrant(), decoratedScope);
		return this.acquireToken(authGrant, clientAuth, policy, callback);
	}

	private void validateInput(final String[] scope, final Object credential) {
		if (scope == null || scope.length == 0) {
			throw new IllegalArgumentException("scope is null or empty");
		}

		Set<String> set = new HashSet<>(Arrays.asList(scope));
		if (set.contains("openid") || set.contains("offline_access")) {
			throw new IllegalArgumentException("Not allowed to pass openid and offline_access as scope values");
		}

		if (credential == null) {
			throw new IllegalArgumentException("credential is null");
		}
	}

	/**
	 * Acquires an access token from the authority on behalf of a user. It
	 * requires using a user token previously received.
	 *
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param assertion
	 *            The access token to use for token acquisition.
	 * @param credential
	 *            The client credential to use for token acquisition.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token and the Access Token's expiration time. Refresh Token
	 *         property will be null for this overload.
	 * @throws AuthenticationException
	 */
	public Future<AuthenticationResult> acquireToken(final String[] scope, final ClientAssertion assertion,
			final ClientCredential credential, final AuthenticationCallback callback) {
		return this.acquireToken(scope, assertion, credential, null, callback);
	}

	/**
	 * Acquires an access token from the authority on behalf of a user. It
	 * requires using a user token previously received.
	 *
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param assertion
	 *            The access token to use for token acquisition.
	 * @param credential
	 *            The client credential to use for token acquisition.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token and the Access Token's expiration time. Refresh Token
	 *         property will be null for this overload.
	 * @throws AuthenticationException
	 */
	public Future<AuthenticationResult> acquireToken(final String[] scope, final ClientAssertion assertion,
			final ClientCredential credential, final String policy, final AuthenticationCallback callback) {

		this.validateInput(scope, credential);
		String[] decoratedScope = this.decorateScope(scope, credential.getClientId());
		Map<String, String> params = new HashMap<String, String>();
		params.put("scope", StringHelper.convertArrayToString(decoratedScope));
		params.put("requested_token_use", "on_behalf_of");
		try {
			AdalAuthorizatonGrant grant = new AdalAuthorizatonGrant(
					new JWTBearerGrant(SignedJWT.parse(assertion.getAssertion())), params);

			final ClientAuthentication clientAuth = new ClientSecretPost(new ClientID(credential.getClientId()),
					new Secret(credential.getClientSecret()));
			return this.acquireToken(grant, clientAuth, policy, callback);
		} catch (final Exception e) {
			throw new AuthenticationException(e);
		}
	}

	/**
	 * Acquires security token from the authority.
	 *
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param credential
	 *            The client credential to use for token acquisition.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token and the Access Token's expiration time. Refresh Token
	 *         property will be null for this overload.
	 */
	public Future<AuthenticationResult> acquireToken(final String[] scope, final ClientCredential credential,
			final AuthenticationCallback callback) {
		return this.acquireToken(scope, credential, null, callback);
	}

	/**
	 * Acquires security token from the authority.
	 *
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param credential
	 *            The client credential to use for token acquisition.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token and the Access Token's expiration time. Refresh Token
	 *         property will be null for this overload.
	 */
	public Future<AuthenticationResult> acquireToken(final String[] scope, final ClientCredential credential,
			String policy, final AuthenticationCallback callback) {
		this.validateInput(scope, credential);
		String[] decoratedScope = this.decorateScope(scope, credential.getClientId());
		final ClientAuthentication clientAuth = new ClientSecretPost(new ClientID(credential.getClientId()),
				new Secret(credential.getClientSecret()));
		final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(new ClientCredentialsGrant(), decoratedScope);
		return this.acquireToken(authGrant, clientAuth, policy, callback);
	}

	/**
	 * Acquires security token from the authority.
	 *
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param credential
	 *            object representing Private Key to use for token acquisition.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token and the Access Token's expiration time. Refresh Token
	 *         property will be null for this overload.
	 * @throws AuthenticationException
	 */
	public Future<AuthenticationResult> acquireToken(final String[] scope, final AsymmetricKeyCredential credential,
			final AuthenticationCallback callback) throws AuthenticationException {
		return this.acquireToken(scope, credential, null, callback);
	}

	/**
	 * Acquires security token from the authority.
	 *
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param credential
	 *            object representing Private Key to use for token acquisition.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token and the Access Token's expiration time. Refresh Token
	 *         property will be null for this overload.
	 * @throws AuthenticationException
	 */
	public Future<AuthenticationResult> acquireToken(final String[] scope, final AsymmetricKeyCredential credential,
			final String policy, final AuthenticationCallback callback) throws AuthenticationException {
		return this.acquireToken(scope,
				JwtHelper.buildJwt(credential, this.authenticationAuthority.getSelfSignedJwtAudience()), callback);
	}

	/**
	 * Acquires security token from the authority using an authorization code
	 * previously received.
	 *
	 * @param authorizationCode
	 *            The authorization code received from service authorization
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param clientId
	 *            The client assertion to use for token acquisition endpoint.
	 * @param redirectUri
	 *            The redirect address used for obtaining authorization code.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByAuthorizationCode(final String authorizationCode,
			final String[] scope, final String clientId, final URI redirectUri, final AuthenticationCallback callback) {
		return this.acquireTokenByAuthorizationCode(authorizationCode, scope, clientId, redirectUri, null, callback);
	}

	/**
	 * Acquires security token from the authority using an authorization code
	 * previously received.
	 *
	 * @param authorizationCode
	 *            The authorization code received from service authorization
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token.
	 * @param clientId
	 *            The client assertion to use for token acquisition endpoint.
	 * @param redirectUri
	 *            The redirect address used for obtaining authorization code.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByAuthorizationCode(final String authorizationCode,
			final String[] scope, final String clientId, final URI redirectUri, final String policy,
			final AuthenticationCallback callback) {

		final ClientAuthentication clientAuth = new ClientAuthenticationPost(ClientAuthenticationMethod.NONE,
				new ClientID(clientId));

		this.validateAuthCodeRequestInput(authorizationCode, redirectUri, clientAuth, scope);
		String[] decoratedScope = this.decorateScope(scope, clientId);
		final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
				new AuthorizationCodeGrant(new AuthorizationCode(authorizationCode), redirectUri), decoratedScope);
		return this.acquireToken(authGrant, clientAuth, policy, callback);
	}

	/**
	 * Acquires security token from the authority using an authorization code
	 * previously received.
	 *
	 * @param authorizationCode
	 *            The authorization code received from service authorization
	 *            endpoint.
	 * @param redirectUri
	 *            The redirect address used for obtaining authorization code.
	 * @param credential
	 *            The client assertion to use for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. It can be null if provided earlier to acquire
	 *            authorizationCode.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByAuthorizationCode(final String authorizationCode,
			final String[] scope, final URI redirectUri, final ClientAssertion credential,
			final AuthenticationCallback callback) {
		return this.acquireTokenByAuthorizationCode(authorizationCode, scope, redirectUri, credential, null, callback);
	}

	/**
	 * Acquires security token from the authority using an authorization code
	 * previously received.
	 *
	 * @param authorizationCode
	 *            The authorization code received from service authorization
	 *            endpoint.
	 * @param redirectUri
	 *            The redirect address used for obtaining authorization code.
	 * @param credential
	 *            The client assertion to use for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. It can be null if provided earlier to acquire
	 *            authorizationCode.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByAuthorizationCode(final String authorizationCode,
			final String[] scope, final URI redirectUri, final ClientAssertion credential, final String policy,
			final AuthenticationCallback callback) {

		this.validateAuthCodeRequestInput(authorizationCode, redirectUri, credential, scope);
		String[] decoratedScope = this.decorateScope(scope, credential.getClientId());
		final ClientAuthentication clientAuth = createClientAuthFromClientAssertion(credential);
		final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
				new AuthorizationCodeGrant(new AuthorizationCode(authorizationCode), redirectUri), decoratedScope);
		return this.acquireToken(authGrant, clientAuth, policy, callback);
	}

	/**
	 * Acquires security token from the authority using an authorization code
	 * previously received.
	 *
	 * @param authorizationCode
	 *            The authorization code received from service authorization
	 *            endpoint.
	 * @param redirectUri
	 *            The redirect address used for obtaining authorization code.
	 * @param credential
	 *            The client credential to use for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. It can be null if provided earlier to acquire
	 *            authorizationCode.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByAuthorizationCode(final String authorizationCode,
			final URI redirectUri, final ClientCredential credential, final String[] scope,
			final AuthenticationCallback callback) {
		return this.acquireTokenByAuthorizationCode(authorizationCode, redirectUri, credential, scope, null, callback);
	}

	/**
	 * Acquires security token from the authority using an authorization code
	 * previously received.
	 *
	 * @param authorizationCode
	 *            The authorization code received from service authorization
	 *            endpoint.
	 * @param redirectUri
	 *            The redirect address used for obtaining authorization code.
	 * @param credential
	 *            The client credential to use for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. It can be null if provided earlier to acquire
	 *            authorizationCode.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByAuthorizationCode(final String authorizationCode,
			final URI redirectUri, final ClientCredential credential, final String[] scope, final String policy,
			final AuthenticationCallback callback) {

		this.validateAuthCodeRequestInput(authorizationCode, redirectUri, credential, scope);
		String[] decoratedScope = this.decorateScope(scope, credential.getClientId());
		final ClientAuthentication clientAuth = new ClientSecretPost(new ClientID(credential.getClientId()),
				new Secret(credential.getClientSecret()));
		final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
				new AuthorizationCodeGrant(new AuthorizationCode(authorizationCode), redirectUri), decoratedScope);
		return this.acquireToken(authGrant, clientAuth, policy, callback);

	}

	/**
	 * Acquires security token from the authority using an authorization code
	 * previously received.
	 *
	 * @param authorizationCode
	 *            The authorization code received from service authorization
	 *            endpoint.
	 * @param redirectUri
	 *            The redirect address used for obtaining authorization code.
	 * @param credential
	 *            object representing Private Key to use for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. It can be null if provided earlier to acquire
	 *            authorizationCode.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 * @throws AuthenticationException
	 *             thrown if {@link AsymmetricKeyCredential} fails to sign the
	 *             JWT token.
	 */
	public Future<AuthenticationResult> acquireTokenByAuthorizationCode(final String authorizationCode,
			final URI redirectUri, final AsymmetricKeyCredential credential, final String[] scope,
			final AuthenticationCallback callback) throws AuthenticationException {
		return this.acquireTokenByAuthorizationCode(authorizationCode, redirectUri, credential, scope, null, callback);
	}

	/**
	 * Acquires security token from the authority using an authorization code
	 * previously received.
	 *
	 * @param authorizationCode
	 *            The authorization code received from service authorization
	 *            endpoint.
	 * @param redirectUri
	 *            The redirect address used for obtaining authorization code.
	 * @param credential
	 *            object representing Private Key to use for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. It can be null if provided earlier to acquire
	 *            authorizationCode.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 * @throws AuthenticationException
	 *             thrown if {@link AsymmetricKeyCredential} fails to sign the
	 *             JWT token.
	 */
	public Future<AuthenticationResult> acquireTokenByAuthorizationCode(final String authorizationCode,
			final URI redirectUri, final AsymmetricKeyCredential credential, final String[] scope, final String policy,
			final AuthenticationCallback callback) throws AuthenticationException {
		return this.acquireTokenByAuthorizationCode(authorizationCode, scope, redirectUri,
				JwtHelper.buildJwt(credential, this.authenticationAuthority.getSelfSignedJwtAudience()), policy,
				callback);
	}

	/**
	 * Acquires a security token from the authority using a Refresh Token
	 * previously received.
	 *
	 * @param refreshToken
	 *            Refresh Token to use in the refresh flow.
	 * @param clientId
	 *            Name or ID of the client requesting the token.
	 * @param credential
	 *            The client assertion used for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. If null, token is requested for the same
	 *            scope refresh token was originally issued for. If passed,
	 *            scope should match the original scope used to acquire refresh
	 *            token unless token service supports refresh token for multiple
	 *            scopes.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByRefreshToken(final String refreshToken, final String clientId,
			final ClientAssertion credential, final String[] scope, final AuthenticationCallback callback) {
		return this.acquireTokenByRefreshToken(refreshToken, clientId, credential, scope, null, callback);
	}

	/**
	 * Acquires a security token from the authority using a Refresh Token
	 * previously received.
	 *
	 * @param refreshToken
	 *            Refresh Token to use in the refresh flow.
	 * @param clientId
	 *            Name or ID of the client requesting the token.
	 * @param credential
	 *            The client assertion used for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. If null, token is requested for the same
	 *            scope refresh token was originally issued for. If passed,
	 *            scope should match the original scope used to acquire refresh
	 *            token unless token service supports refresh token for multiple
	 *            scopes.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByRefreshToken(final String refreshToken, final String clientId,
			final ClientAssertion credential, final String[] scope, final String policy,
			final AuthenticationCallback callback) {
		this.validateRefreshTokenRequestInput(refreshToken, clientId, credential);
		String[] decoratedScope = this.decorateScope(scope, credential.getClientId());
		final ClientAuthentication clientAuth = createClientAuthFromClientAssertion(credential);
		final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
				new RefreshTokenGrant(new RefreshToken(refreshToken)), decoratedScope);
		return this.acquireToken(authGrant, clientAuth, policy, callback);
	}

	/**
	 * Acquires a security token from the authority using a Refresh Token
	 * previously received.
	 *
	 * @param refreshToken
	 *            Refresh Token to use in the refresh flow.
	 * @param credential
	 *            The client credential used for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. If null, token is requested for the same
	 *            scope refresh token was originally issued for. If passed,
	 *            scope should match the original scope used to acquire refresh
	 *            token unless token service supports refresh token for multiple
	 *            scopes.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByRefreshToken(final String refreshToken,
			final ClientCredential credential, final String[] scope, final AuthenticationCallback callback) {
		return this.acquireTokenByRefreshToken(refreshToken, credential, scope, null, callback);
	}

	/**
	 * Acquires a security token from the authority using a Refresh Token
	 * previously received.
	 *
	 * @param refreshToken
	 *            Refresh Token to use in the refresh flow.
	 * @param credential
	 *            The client credential used for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. If null, token is requested for the same
	 *            scope refresh token was originally issued for. If passed,
	 *            scope should match the original scope used to acquire refresh
	 *            token unless token service supports refresh token for multiple
	 *            scopes.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 */
	public Future<AuthenticationResult> acquireTokenByRefreshToken(final String refreshToken,
			final ClientCredential credential, final String[] scope, String policy,
			final AuthenticationCallback callback) {

		final ClientAuthentication clientAuth = new ClientSecretPost(new ClientID(credential.getClientId()),
				new Secret(credential.getClientSecret()));
		String[] decoratedScope = this.decorateScope(scope, credential.getClientId());
		final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
				new RefreshTokenGrant(new RefreshToken(refreshToken)), decoratedScope);
		return this.acquireToken(authGrant, clientAuth, policy, callback);
	}

	/**
	 * Acquires a security token from the authority using a Refresh Token
	 * previously received.
	 *
	 * @param refreshToken
	 *            Refresh Token to use in the refresh flow.
	 * @param credential
	 *            object representing Private Key to use for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. If null, token is requested for the same
	 *            scope refresh token was originally issued for. If passed,
	 *            scope should match the original scope used to acquire refresh
	 *            token unless token service supports refresh token for multiple
	 *            scopes.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 * @throws AuthenticationException
	 *             thrown if {@link AsymmetricKeyCredential} fails to sign the
	 *             JWT token.
	 */
	public Future<AuthenticationResult> acquireTokenByRefreshToken(final String refreshToken,
			final AsymmetricKeyCredential credential, final String[] scope, final AuthenticationCallback callback)
					throws AuthenticationException {
		return this.acquireTokenByRefreshToken(refreshToken, credential, scope, null, callback);
	}

	/**
	 * Acquires a security token from the authority using a Refresh Token
	 * previously received.
	 *
	 * @param refreshToken
	 *            Refresh Token to use in the refresh flow.
	 * @param credential
	 *            object representing Private Key to use for token acquisition.
	 * @param scope
	 *            Identifier of the target scope that is the recipient of the
	 *            requested token. If null, token is requested for the same
	 *            scope refresh token was originally issued for. If passed,
	 *            scope should match the original scope used to acquire refresh
	 *            token unless token service supports refresh token for multiple
	 *            scopes.
	 * @param callback
	 *            optional callback object for non-blocking execution.
	 * @return A {@link Future} object representing the
	 *         {@link AuthenticationResult} of the call. It contains Access
	 *         Token, Refresh Token and the Access Token's expiration time.
	 * @throws AuthenticationException
	 *             thrown if {@link AsymmetricKeyCredential} fails to sign the
	 *             JWT token.
	 */
	public Future<AuthenticationResult> acquireTokenByRefreshToken(final String refreshToken,
			final AsymmetricKeyCredential credential, final String[] scope, String policy,
			final AuthenticationCallback callback) throws AuthenticationException {

		return acquireTokenByRefreshToken(refreshToken, credential.getClientId(),
				JwtHelper.buildJwt(credential, this.authenticationAuthority.getSelfSignedJwtAudience()), scope, policy,
				callback);
	}

	private void validateRefreshTokenRequestInput(final String refreshToken, final String clientId,
			final Object credential) {

		if (StringHelper.isBlank(refreshToken)) {
			throw new IllegalArgumentException("refreshToken is null or empty");
		}

		if (StringHelper.isBlank(clientId)) {
			throw new IllegalArgumentException("clientId is null or empty");
		}

	}

	private AuthenticationResult acquireTokenCommon(final AdalAuthorizatonGrant authGrant,
			final ClientAuthentication clientAuth, final ClientDataHttpHeaders headers, final String policy)
					throws Exception {
		log.debug(LogHelper.createMessage(String.format("Using Client Http Headers: %s", headers),
				headers.getHeaderCorrelationIdValue()));
		this.authenticationAuthority.doInstanceDiscovery(headers.getReadonlyHeaderMap());
		String authority = this.authenticationAuthority.getTokenUri();
		if (!StringHelper.isBlank(policy)) {
			authority += "?p=" + policy;
		}

		final URL url = new URL(authority);
		final AdalTokenRequest request = new AdalTokenRequest(url, clientAuth, authGrant,
				headers.getReadonlyHeaderMap());
		AuthenticationResult result = request.executeOAuthRequestAndProcessResponse();
		return result;
	}

	private void logResult(AuthenticationResult result, ClientDataHttpHeaders headers)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {
		if (!StringHelper.isBlank(result.getAccessToken())) {
			String logMessage = "";
			String accessTokenHash = this.computeSha256Hash(result.getAccessToken());
			if (!StringHelper.isBlank(result.getRefreshToken())) {
				String refreshTokenHash = this.computeSha256Hash(result.getRefreshToken());
				logMessage = String.format("Access Token with hash '%s' and Refresh Token with hash '%s' returned",
						accessTokenHash, refreshTokenHash);
			} else {
				logMessage = String.format("Access Token with hash '%s' returned", accessTokenHash);
			}
			log.debug(LogHelper.createMessage(logMessage, headers.getHeaderCorrelationIdValue()));
		}
	}

	private String computeSha256Hash(String input) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(input.getBytes("UTF-8"));
		byte[] hash = digest.digest();
		return Base64.encodeBase64URLSafeString(hash);
	}

	private ClientAuthentication createClientAuthFromClientAssertion(final ClientAssertion credential) {

		try {
			final Map<String, String> map = new HashMap<String, String>();
			map.put("client_assertion_type", JWTAuthentication.CLIENT_ASSERTION_TYPE);
			map.put("client_assertion", credential.getAssertion());
			return PrivateKeyJWT.parse(map);
		} catch (final ParseException e) {
			throw new AuthenticationException(e);
		}
	}

	/**
	 * Returns the correlation id configured by the user. It does not return the
	 * id automatically generated by the API in case the user does not provide
	 * one.
	 *
	 * @return String value of the correlation id
	 */
	public String getCorrelationId() {
		return correlationId;
	}

	/**
	 * Set optional correlation id to be used by the API. If not provided, the
	 * API generates a random id.
	 *
	 * @param correlationId
	 *            String value
	 */
	public void setCorrelationId(final String correlationId) {
		this.correlationId = correlationId;
	}

	/**
	 * Returns validateAuthority boolean value passed as a constructor
	 * parameter.
	 *
	 * @return boolean value
	 */
	public boolean shouldValidateAuthority() {
		return this.validateAuthority;
	}

	/**
	 * Authority associated with the context instance
	 *
	 * @return String value
	 */
	public String getAuthority() {
		return this.authority;
	}

	private void validateAuthCodeRequestInput(final String authorizationCode, final URI redirectUri,
			final Object credential, final String[] scope) {
		if (StringHelper.isBlank(authorizationCode)) {
			throw new IllegalArgumentException("authorization code is null or empty");
		}

		if (redirectUri == null) {
			throw new IllegalArgumentException("redirect uri is null");
		}

		this.validateInput(scope, credential);
	}

	private String[] decorateScope(String[] scope, String clientId) {
		Set<String> set = new HashSet<>(Arrays.asList(new String[scope.length]));

		if (set.contains(clientId)) {
			if (set.size() > 1) {
				throw new IllegalArgumentException("Client Id can only be passed as a single scope value");
			}

			set = new HashSet<>();
		}

		set.add("openid");
		set.add("offline_access");

		return set.toArray(new String[set.size()]);
	}
}
