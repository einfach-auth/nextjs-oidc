import React from "react";
import * as oauth from "oauth4webapi";
import * as jose from "jose";
import { cookies, headers } from "next/headers";
import { redirect, RedirectType } from "next/navigation";
import { NextRequest, NextResponse } from "next/server";
import type { CookieListItem } from "next/dist/compiled/@edge-runtime/cookies";

/**
 * The result type is used to annotate functions that may return expected errors in a go-like manner.
 */
export type Result<TValue, TError extends string> =
  | [TValue, null]
  | [null, TError];

/**
 * Base identity interface.
 */
export interface Identity {
  [claim: string]: oauth.JsonValue | undefined;
}

/**
 * An encryption service is used to encrypt and decrypt sensitive cookies.
 */
export interface EncryptionService {
  /**
   * Encrypt a string.
   *
   * @param plaintext The plaintext to encrypt, must be at least 1 character long.
   * @returns Success: The encrypted value as string.
   * @returns Error(empty-input): The provided plaintext was an empty string.
   * @returns Error(service-unavailable): The operation could not be performed because a required service, e.g. HashiCorp Vault, was not available or miss-configured.
   * @returns Error(operation-failed): The operation failed due to some reason, e.g. bad key.
   */
  encrypt(
    plaintext: string,
  ): Promise<
    Result<string, "empty-input" | "service-unavailable" | "operation-failed">
  >;

  /**
   * Decrypt a ciphertext.
   *
   * @param ciphertext The ciphertext, must be at least 1 character long.
   * @returns Success: The plaintext value as string.
   * @returns Error(empty-input): The provided ciphertext was an empty string.
   * @returns Error(bad-ciphertext): The provided ciphertext is incorrectly structured.
   * @returns Error(service-unavailable): The operation could not be performed because a required service, e.g. HashiCorp Vault, was not available or miss-configured.
   * @returns Error(operation-failed): The operation failed due to some reason, e.g. bad key.
   */
  decrypt(
    ciphertext: string,
  ): Promise<
    Result<
      string,
      | "empty-input"
      | "bad-ciphertext"
      | "service-unavailable"
      | "operation-failed"
    >
  >;
}

export function buildSecretEncryptionService(
  secret: string,
): EncryptionService {
  if (secret.length < 1) {
    throw new Error("The secret must be at least 1 character long.");
  }

  const { subtle } = globalThis.crypto;
  const deriveKey = async (iv: Uint8Array): Promise<CryptoKey> => {
    const secretKey = await subtle.importKey(
      "raw",
      Buffer.from(secret),
      { name: "PBKDF2" },
      false,
      ["deriveKey", "deriveBits"],
    );

    return await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: iv,
        iterations: 100000,
        hash: "SHA-256",
      },
      secretKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  };

  return {
    encrypt: async (
      plaintext: string,
    ): Promise<
      Result<string, "empty-input" | "service-unavailable" | "operation-failed">
    > => {
      if (plaintext === "") {
        return [null, "empty-input"];
      }

      const plaintextEncoded = new TextEncoder().encode(plaintext);
      const iv = crypto.getRandomValues(new Uint8Array(16));

      try {
        const key = await deriveKey(iv);
        const cipher = await subtle.encrypt(
          {
            name: "AES-GCM",
            iv,
          },
          key,
          plaintextEncoded,
        );
        return [
          `${Buffer.from(iv).toString("base64url")}.${Buffer.from(cipher).toString("base64url")}`,
          null,
        ];
      } catch {
        return [null, "operation-failed"];
      }
    },

    decrypt: async (
      ciphertext: string,
    ): Promise<
      Result<
        string,
        | "empty-input"
        | "bad-ciphertext"
        | "service-unavailable"
        | "operation-failed"
      >
    > => {
      if (ciphertext === "") {
        return [null, "empty-input"];
      }

      const cipherSegments = ciphertext.split(".");

      if (cipherSegments.length !== 2) {
        return [null, "bad-ciphertext"];
      }

      const iv = Buffer.from(cipherSegments[0], "base64url");
      const cipher = Buffer.from(cipherSegments[1], "base64url");

      try {
        const key = await deriveKey(iv);
        const plaintext = await subtle.decrypt(
          { name: "AES-GCM", iv },
          key,
          cipher,
        );
        return [Buffer.from(plaintext).toString(), null];
      } catch {
        return [null, "operation-failed"];
      }
    },
  };
}

/**
 * The various callback errors.
 */
export type CallbackError =
  | "challenge-cookies-read-error" // Unable to read any of the challenge cookies
  | "code-verifier-undefined" // The code verifier cookie was not available
  | "unsupported-flow" // Search parameters indicate an unsupported OAuth2 flow. Implicit and hybrid flows are not supported.
  | "auth-error" // The authorization server responded with an error
  | "token-exchange-failed" // The token exchange failed
  | "setting-cookies-failed" // Unable to set the session cookies
  | "internal-server-error"; // Somthing went wrong, e.g. unable to fetch data due to timeout, etc.

/**
 * The context that is passed to the VerifyIdentity function.
 */
export interface VerifyIdentityContext {
  client: oauth.Client;
  clientAuth: oauth.ClientAuth;
  scope: string;
  authorizationServer: oauth.AuthorizationServer;
  jwks: oauth.JWKS;
  getJWKFromSet: jose.JWTVerifyGetKey;
}

/**
 * Customize the identity verification mechanism in case standard OAuth2 or OIDC are insufficient.
 */
export type VerifyIdentity<TIdentity extends Identity> = (
  context: VerifyIdentityContext,
  idToken: string,
  verifiedIdentity: jose.JWTPayload,
  accessToken: string | undefined,
  verifiedAccessToken: Identity | jose.JWTPayload,
) => Promise<Result<TIdentity | null, "verification-failed">>;

/**
 * Determines the logout behavior.
 *
 * preserve-session: The session tokens are left intact and only the cookies deleted.
 * end-session: The user is redirected to the OIDC end_session_endpoint (OpenID Connect RP-Initiated Logout 1.0).
 * revoke-tokens: The OAuth 2.0 token revocation mechanism is used to invalidate the access and refresh tokens.
 */
export type RevokeSessionOnLogout =
  | "preserve-session"
  | "end-session"
  | "revoke-tokens";

/**
 * The context for authentication and authorization procedures.
 */
interface AuthContext<TIdentity extends Identity = Identity> {
  /**
   * The OAuth 2.0 client.
   */
  client: oauth.Client;

  /**
   * The OAuth 2.0 client authentication.
   */
  clientAuth: oauth.ClientAuth;

  /**
   * The scope that is requested when authenticating a user.
   */
  scope: string;

  /**
   * The OIDC discovery information used to perform the authentication flows.
   */
  authorizationServer: oauth.AuthorizationServer;

  /**
   * The public JSON Web Key Set used to verify tokens and signed payloads.
   */
  jwks: oauth.JWKS;

  /**
   * The public JSON Web Key Set used to verify tokens and signed payloads.
   */
  getJWKFromSet: jose.JWTVerifyGetKey;

  /**
   * The access token type.
   *
   * This determines how the access token is stored as cookie and how it is validated.
   *
   * A "bearer" token is stored encrypted and requires an API call to verify it.
   * A "jwt" is stored in plaintext and is verified using the JWK Set.
   */
  accessTokenType: "jwt" | "bearer";

  /**
   * Determines the way the identity is derived from the session.
   *
   * "id-token": The identity is derived from the ID token payload.
   * "access-token": The identity is derived from the access token.
   * "userinfo": An additional call to the userinfo endpoint is made.
   * "function": A custom function derives the identity.
   */
  verifyIdentity?:
    | "id-token"
    | "access-token"
    | "userinfo"
    | VerifyIdentity<TIdentity>;

  /**
   * Encryption service used to encrypt and decrypt sensitive cookies.
   */
  encryptionService: EncryptionService;

  /**
   * Generates a URL from the provided state to redirect the user to.
   *
   * @param state The state value or null if no state was provided.
   * @returns Returns the URL or Path to which the user is redirected to.
   */
  redirectUrlFromState: (state: string | null) => Promise<string | URL>;

  /**
   * Customizes the authorization URL before adding the generated, required parameters.
   *
   * This function is meant non-essential and non-standard parameters that improve the UX or are required for specific
   * environments.
   *
   * @param searchParams The URLSearchParams of the URL instance that is being used to build the authorizationURL
   */
  customizeAuthorizationUrl: (searchParams: URLSearchParams) => Promise<void>;

  /**
   * The path to the callback endpoint.
   */
  callbackPath: string;

  /**
   * Generates a redirect URL from a callback error.
   *
   * @param error The internal error.
   * @param request The request instance.
   * @returns The URL to which the user should be redirected to upon an error.
   */
  redirectUrlFromCallbackError: (
    error: CallbackError,
    request: NextRequest,
  ) => Promise<URL>;

  /**
   * Determines how a session should be revoked upon the user signing out.
   */
  revokeSessionOnLogout: RevokeSessionOnLogout;

  /**
   * The path for the post_logout_redirect_uri.
   *
   * If undefined the post_logout_redirect_uri search parameter will not be set.
   */
  postLogoutPath: string | undefined;

  /**
   * Defines the expiry time of the nonce and code verifier cookies
   *
   * Value is in Milliseconds,
   *
   * Must be positive and greater than 0.
   */
  signInTTL: number;

  /**
   * The fallback value if the refresh token expiry is not returned with the token response.
   *
   * Value is in Milliseconds,
   *
   * Must be positive and greater than 0.
   */
  fallbackRefreshTokenTTL: number;

  /**
   * The fallback value if the access token expiry is not returned with the token response.
   *
   * Value is in Milliseconds,
   *
   * Must be positive and greater than 0.
   */
  fallbackAccessTokenTTL: number;

  /**
   * The fallback value if the id token expiry is not returned with the token response.
   *
   * Value is in Milliseconds,
   *
   * Must be positive and greater than 0.
   */
  fallbackIdTokenTTL: number;

  /**
   * Configures the cookie names.
   *
   * These names might be modified to match security configurations (e.g. "__Host"-prefix)
   */
  cookieNames: CookieNames;
}

/**
 * An accessor interface for cookies.
 *
 * Hides the complexities of interacting with the various cookies to simplify the usage of cookies in code.
 */
interface AuthCookie {
  /**
   * Check if the cookie is set.
   */
  has(): boolean;

  /**
   * Get the plaintext value of the cookie.
   *
   * @returns Success: The plaintext value or undefined if the cookie was not set.
   * @returns Error("decryption-failed"): The cookie was not readable due to the decryption failing.
   */
  get(): Promise<
    Result<string | undefined, "service-unavailable" | "decryption-failed">
  >;

  /**
   * Set the cookie to the provided value.
   *
   * @param value The value to set.
   * @param expires The expiration date. If undefined no expiration date will be set.
   * @returns Success: null
   * @returns Error("operation-failed"): The cookie cannot be set because it is read-only. (See Next.js docs)
   * @returns Error("encryption-failed"): The value could not be encrypted.
   */
  set(
    value: string,
    expires: Date | number | undefined,
  ): Promise<
    null | "operation-failed" | "service-unavailable" | "encryption-failed"
  >;

  /**
   * Unset the cookie.
   */
  clear(): void;
}

/**
 * Configures the cookie names
 */
export interface CookieNames {
  nonce: string;
  codeVerifier: string;
  idToken: string;
  accessToken: string;
  refreshToken: string;
}

/**
 * Interface to manage all auth cookies.
 */
interface CookieJar {
  /**
   * Stores the nonce during the login attempt.
   *
   * Only used if PKCE is not available.
   */
  nonce: AuthCookie;

  /**
   * Stores the code verifier generated during the login attempt.
   *
   * Always used.
   */
  codeVerifier: AuthCookie;

  /**
   * Stores the id token provided by the OIDC server.
   */
  idToken: AuthCookie;

  /**
   * Stores the access token provided by the OIDC server.
   */
  accessToken: AuthCookie;

  /**
   * Stores the refresh token to refresh the OIDC session.
   */
  refreshToken: AuthCookie;
}

/**
 * Arguments required to construct an auth cookie accessor.
 */
interface AuthCookieArgs {
  /**
   * The name of the cookie.
   */
  name: string;

  /**
   * Determines if the cookie value is encrypted.
   */
  encrypted: boolean;

  /**
   * An optional path for which the cookie is available.
   */
  path?: string | undefined;
}

/**
 * Build an auth cookie accessor from the auth context, provided config and accessor functions.
 *
 * @param context The auth context
 * @param args The cookie configuration
 * @param setCookie The function to set the cookie
 * @param getCookie The function to get the cookie
 * @param deleteCookie The function to delete the cookie
 * @returns An auth cookie accessor object
 */
function buildAuthCookie(
  context: AuthContext,
  args: AuthCookieArgs,
  setCookie: (args: CookieListItem) => void,
  getCookie: (
    name: string,
  ) => Pick<CookieListItem, "name" | "value"> | undefined,
  deleteCookie: (args: Pick<CookieListItem, "name" | "path">) => void,
): AuthCookie {
  if (args.encrypted) {
    return {
      has(): boolean {
        return getCookie(args.name)?.value !== undefined;
      },
      async get(): Promise<
        Result<string | undefined, "service-unavailable" | "decryption-failed">
      > {
        const cipherValue = getCookie(args.name)?.value;
        if (cipherValue === undefined || cipherValue === "") {
          return [undefined, null];
        }
        const [plaintextValue, error] =
          await context.encryptionService.decrypt(cipherValue);
        switch (error) {
          case null:
            break;
          case "service-unavailable":
            return [null, "service-unavailable"];
          default:
            return [null, "decryption-failed"];
        }

        return [plaintextValue, null];
      },
      async set(
        value: string,
        expires: Date | number | undefined,
      ): Promise<
        null | "operation-failed" | "service-unavailable" | "encryption-failed"
      > {
        const [cipherValue, error] =
          await context.encryptionService.encrypt(value);

        switch (error) {
          case null:
            break;
          case "service-unavailable":
            return "service-unavailable";
          default:
            return "encryption-failed";
        }

        try {
          setCookie({
            name: args.name,
            value: cipherValue,
            expires: expires,
            path: args.path,
          });
        } catch {
          return "operation-failed";
        }
        return null;
      },
      clear(): void {
        deleteCookie({
          name: args.name,
          path: args.path,
        });
      },
    };
  }

  return {
    has(): boolean {
      return getCookie(args.name)?.value !== undefined;
    },
    async get(): Promise<Result<string | undefined, "decryption-failed">> {
      return [getCookie(args.name)?.value, null];
    },
    async set(
      value: string,
      expires: Date | number,
    ): Promise<null | "operation-failed" | "encryption-failed"> {
      setCookie({
        name: args.name,
        value: value,
        expires: expires,
        path: args.path,
      });
      return null;
    },
    clear(): void {
      deleteCookie({
        name: args.name,
        path: args.path,
      });
    },
  };
}

/**
 * Build a cookie jar from the auth context and accessor functions.
 *
 * @param context The auth context
 * @param setCookie The function to set the cookie
 * @param getCookie The function to get the cookie
 * @param deleteCookie The function to delete the cookie
 * @returns An cookie jar instance
 */
function buildCookieJar(
  context: AuthContext,
  setCookie: (args: CookieListItem) => void,
  getCookie: (
    name: string,
  ) => Pick<CookieListItem, "name" | "value"> | undefined,
  deleteCookie: (args: Pick<CookieListItem, "name" | "path">) => void,
): CookieJar {
  const authCookie = (args: AuthCookieArgs): AuthCookie =>
    buildAuthCookie(context, args, setCookie, getCookie, deleteCookie);

  return {
    nonce: authCookie({
      name: context.cookieNames.nonce,
      path: context.callbackPath,
      encrypted: true,
    }),
    codeVerifier: authCookie({
      name: context.cookieNames.codeVerifier,
      path: context.callbackPath,
      encrypted: true,
    }),
    idToken: authCookie({
      name: context.cookieNames.idToken,
      encrypted: false,
    }),
    accessToken: authCookie({
      name: context.cookieNames.accessToken,
      encrypted: context.accessTokenType !== "jwt",
    }),
    refreshToken: authCookie({
      name: context.cookieNames.refreshToken,
      encrypted: true,
    }),
  };
}

/**
 * Build the cookie jar from the Next.js cookies() function.
 *
 * @param context The auth context
 * @returns An cookie jar instance
 */
async function cookieJarFromNext(context: AuthContext): Promise<CookieJar> {
  const _cookies = await cookies();
  return buildCookieJar(
    context,
    (args) => _cookies.set(args),
    (name) => _cookies.get(name),
    (args) => _cookies.delete(args),
  );
}

/**
 * Build the cookie jar for a NextRequest instance.
 *
 * @param context The auth context
 * @param request The request instance to build the cookie jar for
 * @returns An cookie jar instance
 */
function cookieJarFromRequest(
  context: AuthContext,
  request: NextRequest,
): CookieJar {
  return buildCookieJar(
    context,
    (args) => request.cookies.set(args),
    (name) => request.cookies.get(name),
    (args) => request.cookies.delete(args.name),
  );
}

/**
 * Build the cookie jar for a NextResponse instance.
 *
 * @param context The auth context
 * @param response The response instance to build the cookie jar for
 * @returns An cookie jar instance
 */
function cookieJarFromResponse(
  context: AuthContext,
  response: NextResponse,
): CookieJar {
  return buildCookieJar(
    context,
    (args) => response.cookies.set(args),
    (name) => response.cookies.get(name),
    (args) => response.cookies.delete(args),
  );
}

/**
 * Internal header used to pass the request URL to react components.
 */
export const REQUEST_URL_HEADER = "next-internal-request-url";

/**
 * Function to access the request URL stored in the headers.
 *
 * @returns Success: The request URL
 * @returns Error("header-not-set"): The required header was not set. Most likely a middleware error.
 */
export async function getRequestUrl(): Promise<Result<URL, "header-not-set">> {
  const _headers = await headers();
  const requestUrl = _headers.get(REQUEST_URL_HEADER);
  if (requestUrl === null) {
    return [null, "header-not-set"];
  }
  return [new URL(requestUrl), null];
}

/**
 * Helper function to set the request URL header on the request instance.
 *
 * @param request the request instance to modify.
 */
function makeRequestUrlAvailable(request: NextRequest): void {
  request.headers.set(REQUEST_URL_HEADER, request.url);
}

/**
 * Generates the authorization URL for the auth context.
 * This function generates the appropriate challenge values based on the OIDC discovery document.
 *
 * @param context The auth context
 * @param plaintextState An optional state in plaintext to continue the session after signing in. Will be encrypted before appending to URL.
 * @returns Success: An object returning the authorization URL for the redirect, the generated code verifier and the nonce if required.
 * @returns Error(authorization-endpoint-undefined): The authorization endpoint is not defined in the OIDC discovery document.
 * @returns Error(request-url-undefined): The request URL is not available. (This is like most likely caused by a miss-configured middleware)
 * @returns Error(encryption-failed): The encryption of the state failed.
 */
async function generateAuthorizationUrl(
  context: AuthContext,
  plaintextState: string | undefined,
): Promise<
  Result<
    {
      authorizationUrl: URL;
      nonce: string | undefined;
      codeVerifier: string;
    },
    | "authorization-endpoint-undefined"
    | "request-url-undefined"
    | "encryption-failed"
  >
> {
  if (context.authorizationServer.authorization_endpoint === undefined) {
    return [null, "authorization-endpoint-undefined"];
  }
  let authorizationUrl: URL;
  try {
    authorizationUrl = new URL(
      context.authorizationServer.authorization_endpoint,
    );
  } catch {
    // If the authorization endpoint is a bad URL we pretend that it is undefined as it has the same effect
    return [null, "authorization-endpoint-undefined"];
  }

  // Generate the challenge values
  const codeVerifier = oauth.generateRandomCodeVerifier();
  const codeChallengeMethod = "S256";
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
  let nonce: string | undefined;
  /**
   * We cannot be sure the AS supports PKCE so we're going to use nonce too. Use of PKCE is
   * backwards compatible even if the AS doesn't support it which is why we're using it regardless.
   */
  if (
    context.authorizationServer.code_challenge_methods_supported?.includes(
      codeChallengeMethod,
    ) !== true
  ) {
    nonce = oauth.generateRandomState();
    authorizationUrl.searchParams.set("nonce", nonce);
  }

  // Build redirection URL
  await context.customizeAuthorizationUrl(authorizationUrl.searchParams);
  authorizationUrl.searchParams.set("client_id", context.client.client_id);

  const [requestUrl, requestUrlError] = await getRequestUrl();
  if (requestUrlError !== null) {
    return [null, "request-url-undefined"];
  }
  const redirectUrl = new URL(context.callbackPath, requestUrl);
  authorizationUrl.searchParams.set("redirect_uri", redirectUrl.toString());
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", context.scope);
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set(
    "code_challenge_method",
    codeChallengeMethod,
  );

  if (plaintextState !== undefined && plaintextState !== "") {
    const [ciphertextState, encryptionError] =
      await context.encryptionService.encrypt(plaintextState);

    if (encryptionError !== null) {
      return [null, "encryption-failed"];
    }
    authorizationUrl.searchParams.set("state", ciphertextState);
  }

  return [
    {
      authorizationUrl,
      nonce,
      codeVerifier,
    },
    null,
  ];
}

/**
 * Options for the sign-in.
 */
export interface SignInOptions {
  /**
   * Provide a custom state during the sign-in.
   */
  state?: string;
}

/**
 * Function to initiate the sign-in procedure.
 * Redirects the user to the authorization URL on success.
 *
 * @param context The auth context.
 * @param options Options to override the sign in.
 * @returns Error(generating-authorization-url-failed): An error occurred while generating the authorization url.
 * @returns Error(setting-cookies-failed): An error occurred while setting the cookies.
 */
async function signIn(
  context: AuthContext,
  options: SignInOptions,
): Promise<
  void | "generating-authorization-url-failed" | "setting-cookies-failed"
> {
  const [authorization, error] = await generateAuthorizationUrl(
    context,
    options.state,
  );
  if (error) {
    return "generating-authorization-url-failed";
  }
  const { authorizationUrl, nonce, codeVerifier } = authorization;

  const signInExpires = Date.now() + context.signInTTL;
  const nextCookieJar = await cookieJarFromNext(context);
  const codeVerifierError = await nextCookieJar.codeVerifier.set(
    codeVerifier,
    signInExpires,
  );
  const nonceError = !!nonce
    ? await nextCookieJar.nonce.set(nonce, signInExpires)
    : null;
  if (codeVerifierError || nonceError) {
    return "setting-cookies-failed";
  }

  redirect(authorizationUrl.toString(), RedirectType.push);
}

/**
 * Revoke a token using the revocation_endpoint.
 *
 * @param context The auth context.
 * @param tokenTypeHint The token type to revoke.
 * @param token The token to revoke.
 * @returns Success: null
 * @returns Error("failed"): The revocation request failed.
 */
async function revokeToken(
  context: AuthContext,
  tokenTypeHint: "access_token" | "refresh_token",
  token: string | undefined,
): Promise<null | "failed"> {
  if (token === undefined) {
    return null;
  }

  try {
    const revocationResponse = await oauth.revocationRequest(
      context.authorizationServer,
      context.client,
      context.clientAuth,
      token,
      {
        additionalParameters: {
          token_type_hint: tokenTypeHint,
        },
      },
    );
    await oauth.processRevocationResponse(revocationResponse);
    return null;
  } catch {
    return "failed";
  }
}

async function generateEndSessionUrl(
  context: AuthContext,
  plaintextState: string | undefined,
  idToken: string | null,
): Promise<
  Result<
    URL,
    "unsupported-endpoint" | "request-url-undefined" | "encryption-failed"
  >
> {
  if (context.authorizationServer.end_session_endpoint === undefined) {
    return [null, "unsupported-endpoint"];
  }
  let endSessionUrl: URL;
  try {
    endSessionUrl = new URL(context.authorizationServer.end_session_endpoint);
  } catch {
    // If the authorization endpoint is a bad URL we pretend that it is undefined as it has the same effect
    return [null, "unsupported-endpoint"];
  }

  endSessionUrl.searchParams.set("client_id", context.client.client_id);

  // As per spec recommendation we pass the id token as id_token_hint
  if (idToken !== null) {
    endSessionUrl.searchParams.set("id_token_hint", idToken);
  }

  if (context.postLogoutPath !== undefined) {
    const [requestUrl, requestUrlError] = await getRequestUrl();
    if (requestUrlError !== null) {
      return [null, "request-url-undefined"];
    }
    const redirectUrl = new URL(context.postLogoutPath, requestUrl);
    endSessionUrl.searchParams.set(
      "post_logout_redirect_uri",
      redirectUrl.toString(),
    );
  }

  if (plaintextState !== undefined && plaintextState !== "") {
    const [ciphertextState, encryptionError] =
      await context.encryptionService.encrypt(plaintextState);

    if (encryptionError !== null) {
      return [null, "encryption-failed"];
    }
    endSessionUrl.searchParams.set("state", ciphertextState);
  }

  return [endSessionUrl, null];
}

/**
 * Options for the sign-out.
 */
export interface SignOutOptions {
  /**
   * The state to determine where to redirect the user to after successfully signing oyt.
   */
  state?: string;

  /**
   * Overrides the default behavior, whether to revoke the session using the revocation_endpoint.
   */
  revokeSession?: RevokeSessionOnLogout;
}

/**
 * Performs the sign-out procedure.
 * Upon successful sign-out the user is redirect to the provided location.
 *
 * @param context The auth context.
 * @param options The sign-out options.
 */
async function signOut(
  context: AuthContext,
  options: SignOutOptions,
): Promise<void> {
  const cookieJar = await cookieJarFromNext(context);
  const revokeSession: RevokeSessionOnLogout =
    options.revokeSession !== undefined
      ? options.revokeSession
      : context.revokeSessionOnLogout;
  let redirectTo: URL | string;

  // Revoke the access and refresh token if configured by default or by options
  switch (revokeSession) {
    case "revoke-tokens":
      const [accessToken, accessTokenError] = await cookieJar.accessToken.get();
      if (accessTokenError === null) {
        await revokeToken(context, "access_token", accessToken);
      }

      const [refreshToken, refreshTokenError] =
        await cookieJar.refreshToken.get();
      if (refreshTokenError === null) {
        await revokeToken(context, "refresh_token", refreshToken);
      }
      redirectTo = await context.redirectUrlFromState(options.state ?? null);
      break;
    case "end-session":
      const [idToken] = await cookieJar.idToken.get();

      const [endSession, endSessionError] = await generateEndSessionUrl(
        context,
        options.state,
        idToken ?? null,
      );
      if (endSessionError !== null) {
        redirectTo = await context.redirectUrlFromState(options.state ?? null);
      } else {
        redirectTo = endSession;
      }

      break;
    default:
      redirectTo = await context.redirectUrlFromState(options.state ?? null);
  }

  // Clear all session cookies
  cookieJar.refreshToken.clear();
  cookieJar.accessToken.clear();
  cookieJar.idToken.clear();

  redirect(redirectTo.toString());
}

/**
 * Set session cookies from token response.
 *
 * @param context The auth context.
 * @param tokenResponse The token response from which to get the access, id and refresh tokens.
 * @param cookieJar The cookie jar to set the cookies on.
 * @returns Success: null
 * @returns Error(setting-cookies-failed): An error occurred while setting one of the cookies.
 */
async function setSessionCookies(
  context: AuthContext,
  tokenResponse: oauth.TokenEndpointResponse,
  cookieJar: CookieJar,
): Promise<null | "id-token-verification-failed" | "setting-cookies-failed"> {
  // Get access, id and refresh token cookies
  const {
    access_token,
    id_token,
    expires_in,
    refresh_token,
    refresh_expires_in,
  } = tokenResponse;

  if (id_token) {
    let expires: number;
    try {
      const { payload } = await jose.jwtVerify(id_token, context.getJWKFromSet);
      expires =
        !!payload.exp && payload.exp > 0
          ? payload.exp * 1000
          : Date.now() + context.fallbackIdTokenTTL;
    } catch {
      return "id-token-verification-failed";
    }

    const error = await cookieJar.idToken.set(
      id_token,
      expires ?? context.fallbackIdTokenTTL,
    );
    if (error) {
      return "setting-cookies-failed";
    }
  }

  if (access_token) {
    const expiresIn = !!expires_in
      ? expires_in * 1000
      : context.fallbackAccessTokenTTL;
    const expires = Date.now() + expiresIn;

    const error = await cookieJar.accessToken.set(
      access_token,
      expires ?? context.fallbackAccessTokenTTL,
    );

    if (error) {
      return "setting-cookies-failed";
    }
  }

  if (refresh_token) {
    const expiresIn =
      typeof refresh_expires_in === "number" &&
      Number.isInteger(refresh_expires_in)
        ? refresh_expires_in * 1000
        : context.fallbackRefreshTokenTTL;
    const expires = Date.now() + expiresIn;

    const error = await cookieJar.refreshToken.set(refresh_token, expires);

    if (error) {
      return "setting-cookies-failed";
    }
  }

  return null;
}

/**
 * Function to handle the callback from the OIDC server.
 *
 * @param context The auth context.
 * @param request The request instance from the endpoint.
 * @returns A redirect response.
 */
async function callback(
  context: AuthContext,
  request: NextRequest,
): Promise<NextResponse> {
  const requestCookieJar = cookieJarFromRequest(context, request);
  const response = NextResponse.redirect(new URL(request.url).origin);
  const responseCookieJar = cookieJarFromResponse(context, response);
  // Purge used code verifier and nonce cookies
  responseCookieJar.codeVerifier.clear();
  responseCookieJar.nonce.clear();

  const errorResponse = async (error: CallbackError): Promise<NextResponse> => {
    const redirectUrl = await context.redirectUrlFromCallbackError(
      error,
      request,
    );
    response.headers.set("Location", redirectUrl.toString());
    return response;
  };

  const [codeVerifier, codeVerifierError] =
    await requestCookieJar.codeVerifier.get();
  const [nonce, nonceError] = await requestCookieJar.nonce.get();

  // If we are unable to read the cookies, something went wrong
  if (nonceError || codeVerifierError) {
    return await errorResponse("challenge-cookies-read-error");
  }

  // The code verifier is expected to be available, otherwise the login window has expired
  if (!codeVerifier) {
    return await errorResponse("code-verifier-undefined");
  }

  const currentUrl: URL = new URL(request.url);
  let params: URLSearchParams;
  try {
    params = oauth.validateAuthResponse(
      context.authorizationServer,
      context.client,
      currentUrl,
      oauth.skipStateCheck,
    );
  } catch (e) {
    let error: CallbackError = "internal-server-error";
    if (e instanceof oauth.AuthorizationResponseError) {
      error = "auth-error";
    }
    if (e instanceof oauth.UnsupportedOperationError) {
      error = "unsupported-flow";
    }
    return await errorResponse(error);
  }

  let tokenResponse: oauth.TokenEndpointResponse;
  try {
    const callbackUrl = new URL(context.callbackPath, request.url);
    const response = await oauth.authorizationCodeGrantRequest(
      context.authorizationServer,
      context.client,
      context.clientAuth,
      params,
      callbackUrl.toString(),
      codeVerifier,
    );

    tokenResponse = await oauth.processAuthorizationCodeResponse(
      context.authorizationServer,
      context.client,
      response,
      { expectedNonce: nonce },
    );
  } catch (e) {
    let error: CallbackError = "internal-server-error";
    if (
      e instanceof oauth.AuthorizationResponseError ||
      e instanceof oauth.ResponseBodyError
    ) {
      error = "token-exchange-failed";
    }
    return await errorResponse(error);
  }

  const error = await setSessionCookies(
    context,
    tokenResponse,
    responseCookieJar,
  );
  if (error) {
    return await errorResponse("setting-cookies-failed");
  }

  let returnUrl = await context.redirectUrlFromState(params.get("state"));
  response.headers.set("Location", returnUrl.toString());
  return response;
}

/**
 * Purges the session cookies.
 *
 * @param cookieJar The cookie jar instance to perform the operation on
 */
function purgeSessionCookies(cookieJar: CookieJar): void {
  cookieJar.idToken.clear();
  cookieJar.accessToken.clear();
  cookieJar.refreshToken.clear();
}

/**
 * The middleware for authentication to work correctly.
 *
 * Verifies the session and refreshes the session if necessary and possible.
 *
 * @param context The auth context.
 * @param request The request instance passed from Next.js.
 * @returns The generated response to continue the middleware chain.
 */
async function middleware(
  context: AuthContext,
  request: NextRequest,
): Promise<NextResponse> {
  const requestCookieJar = cookieJarFromRequest(context, request);

  // Existing session
  {
    // Successfully authorized identity
    if (requestCookieJar.accessToken.has() && requestCookieJar.idToken.has()) {
      return NextResponse.next({
        request,
      });
    }
  }

  // Session refresh
  {
    const [refreshToken, refreshTokenError] =
      await requestCookieJar.refreshToken.get();

    // If the refresh token is not usable or present simply continue unauthenticated
    if (refreshTokenError !== null || refreshToken === undefined) {
      const response = NextResponse.next({
        request,
      });
      if (refreshTokenError !== "service-unavailable") {
        purgeSessionCookies(cookieJarFromResponse(context, response));
      }

      return response;
    }

    // Refresh the session
    let tokenResponse: oauth.TokenEndpointResponse;
    try {
      const response = await oauth.refreshTokenGrantRequest(
        context.authorizationServer,
        context.client,
        context.clientAuth,
        refreshToken,
        {},
      );

      tokenResponse = await oauth.processRefreshTokenResponse(
        context.authorizationServer,
        context.client,
        response,
      );
    } catch (e) {
      const response = NextResponse.next({ request });
      // We only need to purge the session cookies if the refresh failed for being invalid
      if (
        e instanceof oauth.AuthorizationResponseError ||
        e instanceof oauth.ResponseBodyError
      ) {
        purgeSessionCookies(cookieJarFromResponse(context, response));
      }
      return response;
    }

    // Successfully refreshed the session, set the internal identity request header and update the session cookies
    const response = NextResponse.next({
      request,
    });
    await setSessionCookies(
      context,
      tokenResponse,
      cookieJarFromResponse(context, response),
    );
    return response;
  }
}

/**
 * Represents a verified session.
 */
export interface VerifiedSession<TIdentity extends Identity> {
  status: "authenticated";
  identity: TIdentity;
  accessToken: string;
  idToken: string;
}

/**
 * Represents a session that failed the verification.
 */
export interface UnverifiedSession {
  status:
    | "no-active-session"
    | "internal-error"
    | "verification-failed"
    | "not-authorized"
    | "expired";
}

export type Session<TIdentity extends Identity> =
  | VerifiedSession<TIdentity>
  | UnverifiedSession;

/**
 * Verifies the id token against the known JWK set.
 *
 * @param context The auth context
 * @param cookieJar The cookie jar to read the cookies from
 * @returns Success: The object generated from the parsed payload
 * @returns Error("verification-failed"): The verification failed
 */
async function verifyIdToken(
  context: AuthContext,
  cookieJar: CookieJar,
): Promise<
  Result<
    { idToken: string; verifiedIdToken: jose.JWTPayload },
    "unset" | "cookie-error" | "verification-failed"
  >
> {
  const [idToken, idTokenCookieError] = await cookieJar.idToken.get();

  if (idTokenCookieError !== null) {
    return [null, "cookie-error"];
  }

  if (idToken === undefined) {
    return [null, "unset"];
  }

  try {
    const { payload } = await jose.jwtVerify(idToken, context.getJWKFromSet);
    return [{ idToken, verifiedIdToken: payload }, null];
  } catch (e) {
    return [null, "verification-failed"];
  }
}

/**
 * Verifies the access token.
 *
 * @param context The auth context
 * @param cookieJar The cookie jar to read the cookies from
 * @returns Success: The object generated from the parsed payload
 * @returns Error("verification-failed"): The verification failed
 */
async function verifyAccessToken(
  context: AuthContext,
  cookieJar: CookieJar,
): Promise<
  Result<
    { accessToken: string; verifiedAccessToken: jose.JWTPayload | Identity },
    "unset" | "cookie-error" | "verification-failed"
  >
> {
  const [accessToken, accessTokenCookieError] =
    await cookieJar.accessToken.get();

  if (accessTokenCookieError !== null) {
    return [null, "cookie-error"];
  }

  if (accessToken === undefined) {
    return [null, "unset"];
  }

  let verifiedAccessToken: jose.JWTPayload | Identity;
  switch (context.accessTokenType) {
    case "jwt":
      try {
        const { payload } = await jose.jwtVerify(
          accessToken,
          context.getJWKFromSet,
        );
        // typing can be cast without issues as payload is expected to be valid json
        verifiedAccessToken = payload;
        break;
      } catch (e) {
        return [null, "verification-failed"];
      }
    case "bearer":
      try {
        const introspectResponse = await oauth.introspectionRequest(
          context.authorizationServer,
          context.client,
          context.clientAuth,
          accessToken,
        );
        verifiedAccessToken = await oauth.processIntrospectionResponse(
          context.authorizationServer,
          context.client,
          introspectResponse,
        );
        break;
      } catch {
        return [null, "verification-failed"];
      }
    default:
      return [null, "verification-failed"];
  }
  return [
    {
      accessToken,
      verifiedAccessToken,
    },
    null,
  ];
}

/**
 * Verifies the identity based on the `context.verifyIdentity` property.
 *
 * @param context The auth context
 * @param idToken The id token
 * @param verifiedIdToken The parsed and verified id token
 * @param accessToken The access token
 * @param verifiedAccessToken The parsed and verified access token
 */
async function verifyIdentity<TIdentity extends Identity>(
  context: AuthContext<TIdentity>,
  idToken: string,
  verifiedIdToken: jose.JWTPayload,
  accessToken: string,
  verifiedAccessToken: jose.JWTPayload | Identity,
): Promise<
  Result<
    TIdentity | null,
    "unsupported-identity-source" | "verification-failed"
  >
> {
  if (typeof context.verifyIdentity === "function") {
    return await context.verifyIdentity(
      {
        client: context.client,
        clientAuth: context.clientAuth,
        authorizationServer: context.authorizationServer,
        scope: context.scope,
        jwks: context.jwks,
        getJWKFromSet: context.getJWKFromSet,
      },
      idToken,
      verifiedIdToken,
      accessToken,
      verifiedAccessToken,
    );
  }

  switch (context.verifyIdentity) {
    case "id-token":
      return [verifiedIdToken as TIdentity, null];
    case "access-token":
      return [verifiedAccessToken as TIdentity, null];
    case "userinfo":
      try {
        const userInfoResponse = await oauth.userInfoRequest(
          context.authorizationServer,
          context.client,
          accessToken,
        );
        const identity = await oauth.processUserInfoResponse(
          context.authorizationServer,
          context.client,
          oauth.skipSubjectCheck,
          userInfoResponse,
        );
        return [identity as unknown as TIdentity, null];
      } catch {
        return [null, "verification-failed"];
      }
    default:
      return [null, "unsupported-identity-source"];
  }
}

/**
 * Generates the session from cookies.
 *
 * @param context The auth context
 * @returns The session instance if a verified session exists or null if not.
 */
async function getSession<TIdentity extends Identity>(
  context: AuthContext<TIdentity>,
): Promise<Session<TIdentity>> {
  const cookieJar = await cookieJarFromNext(context);
  const [
    [id, idTokenVerificationError],
    [access, accessTokenVerificationError],
  ] = await Promise.all([
    verifyIdToken(context, cookieJar),
    verifyAccessToken(context, cookieJar),
  ]);

  if (
    idTokenVerificationError === "unset" &&
    accessTokenVerificationError === "unset"
  ) {
    return { status: "no-active-session" };
  }

  if (idTokenVerificationError || accessTokenVerificationError) {
    return { status: "verification-failed" };
  }

  const { idToken, verifiedIdToken } = id;
  const { accessToken, verifiedAccessToken } = access;

  const [identity, identityError] = await verifyIdentity(
    context,
    idToken,
    verifiedIdToken,
    accessToken,
    verifiedAccessToken,
  );

  return (
    identityError === null && identity !== null
      ? {
          identity,
          idToken,
          accessToken,
          status: "authenticated",
        }
      : { status: "verification-failed" }
  ) satisfies Session<TIdentity>;
}

/**
 * Get the authorization server from the discovery endpoint
 *
 * @param issuer The issuer URL
 * @returns Success: The discovery information
 * @returns Error("request-error"): The request failed or returned with an unsuccessful or bad response
 */
async function fetchAuthorizationServer(
  issuer: URL,
): Promise<Result<oauth.AuthorizationServer, "request-error">> {
  try {
    const discoveryResponse = await oauth.discoveryRequest(issuer);
    const authorizationServer = await oauth.processDiscoveryResponse(
      issuer,
      discoveryResponse,
    );
    return [authorizationServer, null];
  } catch (e) {
    return [null, "request-error"];
  }
}

/**
 * Fetches the JSON Web Key Set form the jwks endpoint of the authorization server.
 *
 * @param authorizationServer The authorization server
 * @returns Success: The JSON Web Key Set
 * @returns Error("request-error"): The request failed or returned with an unsuccessful or bad response
 */
async function fetchJWKS(
  authorizationServer: oauth.AuthorizationServer,
): Promise<Result<oauth.JWKS, "request-error" | "jwks-not-supported">> {
  if (authorizationServer.jwks_uri === undefined) {
    return [null, "jwks-not-supported"];
  }

  try {
    const jwksResponse = await fetch(authorizationServer.jwks_uri);
    if (
      !jwksResponse.ok ||
      jwksResponse.headers.get("Content-Type") !== "application/json"
    ) {
      return [null, "request-error"];
    }

    const jwks: oauth.JWKS = await jwksResponse.json();
    return [jwks, null];
  } catch {
    return [null, "request-error"];
  }
}

/**
 * Options for a cached function
 */
export interface CacheOptions {
  /**
   * The duration in milliseconds for which the result is cached.
   *
   * Value must be a positive number greater than 0.
   */
  duration?: number;
}

/**
 * Type for the cache wrapper function.
 */
export type Cache = <TValue extends oauth.JsonValue, TError extends string>(
  getter: () => Promise<Result<TValue, TError>>,
  options?: CacheOptions,
) => () => Promise<Result<TValue, TError>>;

/**
 * Cache function implementing caching using a local variable.
 *
 * Implementation is synchronous, the Promise is returned immediately and not awaited.
 * Expiry is only set upon completing the Promise.
 *
 * On error, the expiry is randomly set between 1 to 5 seconds.
 *
 * @param getter The getter function
 * @param duration The duration for which the result is cached
 * @returns A function that returns a promise that resolves to the cached value
 */
function functionCache<TValue extends oauth.JsonValue, TError extends string>(
  getter: () => Promise<Result<TValue, TError>>,
  { duration }: CacheOptions = {},
): () => Promise<Result<TValue, TError>> {
  let cachedValue: {
    promise: Promise<Result<TValue, TError>>;
    expiresAt: number | undefined;
  } | null = null;

  const get = async () => {
    const result = await getter();
    const [_, error] = result;
    if (cachedValue !== null) {
      if (error !== null) {
        cachedValue.expiresAt = Date.now() + Math.random() * 4000 + 1000; // wait at least 1 second, at most 5.
      } else {
        cachedValue.expiresAt =
          duration !== undefined ? Date.now() + duration : undefined;
      }
    }
    return result;
  };

  return () => {
    if (
      cachedValue === null ||
      (cachedValue.expiresAt !== undefined &&
        cachedValue.expiresAt < Date.now())
    ) {
      cachedValue = {
        promise: get(),
        expiresAt: undefined,
      };
    }
    return cachedValue.promise;
  };
}

/**
 * The configuration options for the authentication provider.
 */
export interface AuthenticationProviderConfig<TIdentity extends Identity> {
  /**
   * The issuer URL of the OIDC server.
   */
  issuer: URL;

  /**
   * The client used for interacting with the OIDC server.
   */
  client: oauth.Client;

  /**
   * The client authentication used for interacting with the OIDC server.
   */
  clientAuth: oauth.ClientAuth;

  /**
   * The scope to request when authenticating users.
   */
  scope: string;

  /**
   * The encryption service that is used for encrypting sensitive cookies.
   */
  encryptionService: EncryptionService;

  /**
   * The type of access token that is used.
   *
   * This has implications on cookies and verification mechanisms:
   * Bearer:
   * - The cookie is encrypted.
   * - Verification is only via API call possible.
   * JWT:
   * - The cookie is in plaintext.
   * - Verification can be done via signature verification.
   *
   * @default "bearer"
   */
  accessTokenType?: "bearer" | "jwt";

  /**
   * Determines the identity verification mechanism.
   *
   * Optionally can pass in a function to customize the behavior.
   * This function is called in the middleware once with existing credentials and once after a successful refresh.
   *
   * @default "id-token"
   */
  verifyIdentity?:
    | "id-token"
    | "access-token"
    | "userinfo"
    | VerifyIdentity<TIdentity>;

  /**
   * Generates a URL from the provided state to redirect the user to.
   *
   * @param state The state value or null if no state was provided.
   * @returns Returns the URL or Path to which the user is redirected to.
   */
  redirectUrlFromState?: (state: string | null) => Promise<string | URL>;

  /**
   * Generates a redirect URL from a callback error.
   *
   * @param error The internal error.
   * @param request The request instance.
   * @returns The URL to which the user should be redirected to upon an error.
   */
  redirectUrlFromCallbackError?: (
    error: CallbackError,
    request: NextRequest,
  ) => Promise<URL>;

  /**
   * Configures the sign-out behavior.
   *
   * Allows to end the OIDC session once a user logs out.
   *
   * @default "revoke-tokens"
   */
  revokeSessionOnLogout?: RevokeSessionOnLogout;

  /**
   * The path for the post_logout_redirect_uri.
   *
   * If undefined the post_logout_redirect_uri search parameter will not be set.
   *
   * @default undefined
   */
  postLogoutPath?: string;

  /**
   * This function is invoked first before standard OAuth2 parameters are added.
   *
   * Use this function to add parameters that are not essential to the OAuth2 protocol. e.g. login_hint or prompt
   *
   * @param searchParams The URLSearchParams instance of the authorization url
   */
  customizeAuthorizationUrl?: (searchParams: URLSearchParams) => Promise<void>;

  /**
   * The callback path for the OAuth2 redirect url
   *
   * @default "/auth/callback"
   */
  callbackPath?: string;

  /**
   * Defines the expiry time of the nonce and code verifier cookies
   *
   * Value is in Milliseconds,
   *
   * Must be positive and greater than 0.
   *
   * @default 600_000 = 10 minutes
   */
  signInTTL?: number;

  /**
   * The fallback value if the refresh token expiry is not returned with the token response.
   *
   * Value is in Milliseconds,
   *
   * Must be positive and greater than 0.
   *
   * @default 86_400_000 = 24h
   */
  fallbackRefreshTokenTTL?: number;

  /**
   * The fallback value if the access token expiry is not returned with the token response.
   *
   * Value is in Milliseconds,
   *
   * Must be positive and greater than 0.
   *
   * @default 1_800_000 = 30 minutes
   */
  fallbackAccessTokenTTL?: number;

  /**
   * The fallback value if the id token expiry is not returned with the token response.
   *
   * Value is in Milliseconds,
   *
   * Must be positive and greater than 0.
   *
   * @default 1_800_000 = 30 minutes
   */
  fallbackIdTokenTTL?: number;

  /**
   * Configures the cookie names.
   *
   * These names might be modified to match security configurations (e.g. "__Host"-prefix)
   *
   * @default {
   *     nonce: "SIMPLE_AUTH.NONCE",
   *     codeVerifier: "SIMPLE_AUTH.CODE_VERIFIER",
   *     idToken: "SIMPLE_AUTH.ID_TOKEN",
   *     accessToken: "SIMPLE_AUTH.ACCESS_TOKEN",
   *     refreshToken: "SIMPLE_AUTH.REFRESH_TOKEN",
   *   }
   */
  cookieNames?: CookieNames;

  /**
   * The caching function used to cache discovery responses and public keys.
   *
   * This can be customized to fit the best practices for caching in the deployment environment. (e.g. redis or hosted alternatives)
   */
  cache?: Cache;

  /**
   * The duration for which the JWK Set is cached.
   *
   * Value is in Milliseconds,
   *
   * @default 43_200_000 = 12 Hours
   */
  jwksCachingDuration?: number;
}

/**
 * Describes the functionality an authentication provider exposes for the developer.
 */
export interface AuthenticationProvider<TIdentity extends Identity> {
  /**
   * Initiates the sign-in procedure.
   *
   * On successful operation the user is redirected to the authorization endpoint of the OIDC server.
   *
   * @param options Configures the sign-in behavior, e.g. where to redirect the user after successful sign-in
   * @returns Error("generating-authorization-url-failed"): The authorization URL could not be generated
   * @returns Error("setting-cookies-failed"): The code verifier or nonce cookies could not be set
   * @returns Error(preparing-context-failed"): The auth context could not be provided
   */
  signIn: (
    options?: SignInOptions,
  ) => Promise<
    | void
    | "generating-authorization-url-failed"
    | "setting-cookies-failed"
    | "preparing-context-failed"
  >;

  /**
   * Initiate the sign-out procedure.
   *
   * On successful operation redirects the user, deletes the session cookies.
   * Depending on the configuration also initiates the corresponding session revocation.
   *
   * @param options Configures the sign-out behavior, e.g. where to redirect the user after successful sign-out
   * @returns Error("preparing-context-failed"): The auth context could not be provided
   */
  signOut: (
    options?: SignOutOptions,
  ) => Promise<void | "preparing-context-failed">;

  /**
   * The handler function for the callback endpoint.
   *
   * Implements the OAuth 2.0 callback.
   *
   * @param request The request object
   * @returns The generated response, will always return a redirect.
   */
  callback: (request: NextRequest) => Promise<NextResponse>;

  /**
   * The middleware handler for the Next.js server.
   *
   * Takes care of refreshing the session if necessary.
   *
   * @param request The request object from the previous middleware call
   * @returns The generated response.
   */
  middleware: (request: NextRequest) => Promise<NextResponse>;

  /**
   * This function implements the preload pattern for the session object.
   */
  preloadSession: () => void;

  /**
   * Gets the current session for the request.
   *
   * @returns The cached session instance.
   */
  session: () => Promise<Session<TIdentity>>;
}

/**
 * Configures an authentication provider.
 *
 * @returns Returns the generated AuthenticationProvider instance.
 */
export function configureAuthenticationProvider<TIdentity extends Identity>({
  issuer,
  client,
  clientAuth,
  scope,
  encryptionService,
  accessTokenType = "bearer",
  verifyIdentity = "id-token",
  revokeSessionOnLogout = "revoke-tokens",
  postLogoutPath = undefined,
  redirectUrlFromState = (state) => Promise.resolve(!!state ? state : "/"),
  redirectUrlFromCallbackError = (_, request) =>
    Promise.resolve(new URL(new URL(request.url).origin)),
  customizeAuthorizationUrl = (_) => Promise.resolve(),
  callbackPath = "/auth/callback",
  signInTTL = 600_000,
  fallbackRefreshTokenTTL = 86_400_000,
  fallbackAccessTokenTTL = 1_800_000,
  fallbackIdTokenTTL = 1_800_000,
  cookieNames = {
    nonce: "SIMPLE_AUTH.NONCE",
    codeVerifier: "SIMPLE_AUTH.CODE_VERIFIER",
    idToken: "SIMPLE_AUTH.ID_TOKEN",
    accessToken: "SIMPLE_AUTH.ACCESS_TOKEN",
    refreshToken: "SIMPLE_AUTH.REFRESH_TOKEN",
  },
  cache = functionCache,
  jwksCachingDuration = 43_200_000,
}: AuthenticationProviderConfig<TIdentity>): AuthenticationProvider<TIdentity> {
  const getAuthorizationServer = cache<
    oauth.AuthorizationServer,
    "request-error"
  >(() => fetchAuthorizationServer(issuer));

  // Preload authorization server
  getAuthorizationServer();

  // @ts-expect-error
  const getJWKS = cache<oauth.JWKS, "jwks-not-supported" | "request-error">(
    async () => {
      const [authorizationServer, authorizationServerError] =
        await getAuthorizationServer();
      if (authorizationServerError !== null) {
        return "request-error";
      }
      return await fetchJWKS(authorizationServer);
    },
    { duration: jwksCachingDuration },
  );

  // Preload JWK Set
  getJWKS();

  const getContext = async (): Promise<
    Result<AuthContext<TIdentity>, "authorization-server-error" | "jwks-error">
  > => {
    const [authorizationServer, authorizationServerError] =
      await getAuthorizationServer();
    if (authorizationServerError !== null) {
      return [null, "authorization-server-error"];
    }

    const [jwks, jwksError] = await getJWKS();

    if (jwksError !== null) {
      return [null, "jwks-error"];
    }

    const getJWKFromSet = jose.createLocalJWKSet(
      jwks as jose.JSONWebKeySet, // This casting is fine, as jose and oauth4webapi define the same standardized interface with slightly different constraints
    );

    const context = {
      client,
      clientAuth,
      scope,
      encryptionService,
      revokeSessionOnLogout,
      postLogoutPath,
      redirectUrlFromState,
      redirectUrlFromCallbackError,
      customizeAuthorizationUrl,
      callbackPath,
      accessTokenType,
      verifyIdentity,
      signInTTL,
      fallbackRefreshTokenTTL,
      fallbackAccessTokenTTL,
      fallbackIdTokenTTL,
      cookieNames,
      authorizationServer,
      jwks,
      getJWKFromSet,
    } satisfies AuthContext<TIdentity>;

    return [context, null];
  };

  const session: () => Promise<Session<TIdentity>> = React.cache(async () => {
    const [context, contextError] = await getContext();
    if (contextError !== null) {
      return {
        status: "internal-error",
      };
    }
    return await getSession(context);
  });

  return {
    async signIn(
      options?: SignInOptions,
    ): Promise<
      | void
      | "generating-authorization-url-failed"
      | "setting-cookies-failed"
      | "preparing-context-failed"
    > {
      const [context, contextError] = await getContext();
      if (contextError !== null) {
        return "preparing-context-failed";
      }
      return await signIn(context, options ?? {});
    },
    async signOut(
      options?: SignOutOptions,
    ): Promise<void | "preparing-context-failed"> {
      const [context, contextError] = await getContext();
      if (contextError !== null) {
        return "preparing-context-failed";
      }
      return await signOut(context, options ?? {});
    },
    async callback(request: NextRequest): Promise<NextResponse> {
      const [context, contextError] = await getContext();
      if (contextError !== null) {
        return new NextResponse(null, {
          status: 500,
        });
      }
      return await callback(context, request);
    },
    async middleware(request: NextRequest): Promise<NextResponse> {
      makeRequestUrlAvailable(request);

      const [context, contextError] = await getContext();
      if (contextError !== null) {
        return NextResponse.next({
          request,
        });
      }

      return await middleware(context, request);
    },
    preloadSession(): void {
      // Don't await the session as we only want to initiate the loading but don't care about the result
      session();
    },
    session,
  } satisfies AuthenticationProvider<TIdentity>;
}
