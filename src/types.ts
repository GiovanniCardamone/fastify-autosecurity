type SecurityAgent<T> = T | Promise<T> | undefined | Promise<undefined>

type ValidateScopeFn<T> = (
	retrived: T,
	scopes: string[]
) => boolean | Promise<boolean>

export type OAS2_SecurityType = OAS2_BasicAuth | ApiKeyAuth
export type OAS3_SecurityType = OAS3_BasicAuth | ApiKeyAuth | BearerAuth

export type SecurityTypes = BasicAuth | ApiKeyAuth | BearerAuth
// | OAuth2Auth | OpenIdConnectAuth

export type StrictSecurity<T> =
	| StrictBasicAuthSecurity<T>
	| StrictApiKeySecurity<T>
	| StrictBearerSecurity<T>
// | StrictOAuth2Security<T>
// | StrictOpenIdConnectSecurity<T>

// ======== BASIC AUTH

export type BasicAuth = OAS2_BasicAuth | OAS3_BasicAuth

export interface OAS2_BasicAuth {
	type: 'basic'
}

export interface OAS3_BasicAuth {
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
