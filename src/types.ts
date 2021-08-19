type SecurityAgent<T> = T | Promise<T> | undefined | Promise<undefined>

type ValidateScopeFn<T> = (
	retrived: T,
	scopes: string[]
) => boolean | Promise<boolean>

export type SecurityTypes = BasicAuth | ApiKeyAuth | BearerAuth
// | OAuth2Auth | OpenIdConnectAuth

export type StrictSecurity<T> =
	| StrictBasicAuthSecurity<T>
	| StrictApiKeySecurity<T>
	| StrictBearerSecurity<T>
// | StrictOAuth2Security<T>
// | StrictOpenIdConnectSecurity<T>

// ======== BASIC AUTH

export type BasicAuth = BasicAuth_OAS2 | BasicAuth_OAS3

export interface BasicAuth_OAS2 {
	type: 'basic'
}

export interface BasicAuth_OAS3 {
	type: 'http'
	scheme: 'basic'
}

export interface StrictBasicAuthSecurity<T extends unknown> {
	security: BasicAuth
	handle: (username: string, password: string) => SecurityAgent<T>
	scopes: ValidateScopeFn<T>
}

// ======== APIKEY AUTH

export interface ApiKeyAuth {
	type: 'apiKey'
	in: 'header' | 'query'
	name: string
}

export interface StrictApiKeySecurity<T extends unknown> {
	security: ApiKeyAuth
	handle: (apikey: string) => SecurityAgent<T>
	scopes: ValidateScopeFn<T>
}

// ======== BEARER AUTH

export interface BearerAuth {
	type: 'http'
	scheme: 'bearer'
}

export interface StrictBearerSecurity<T extends unknown> {
	security: BearerAuth
	handle: (token: string) => SecurityAgent<T>
	scopes: ValidateScopeFn<T>
}
