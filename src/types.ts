type SecurityAgent<T> = T | Promise<T> | undefined | Promise<undefined>

type Scope<T> = (retrived: T, scopes: string[]) => boolean | Promise<boolean>

type ValidateScope = (scope: string) => boolean

export type OAS2_SecurityType = OAS2_BasicAuth | ApiKeyAuth
export type OAS3_SecurityType =
	| OAS3_BasicAuth
	| ApiKeyAuth
	| BearerAuth
	| OpenIdConnectAuth

export type SecurityTypes =
	| BasicAuth
	| ApiKeyAuth
	| BearerAuth
	| OpenIdConnectAuth
// | OAuth2Auth | OpenIdConnectAuth

export type StrictSecurity<T> =
	| StrictBasicAuthSecurity<T>
	| StrictApiKeySecurity<T>
	| StrictBearerSecurity<T>
	| StrictOpenIdConnectSecurity<T>
// | StrictOAuth2Security<T>

// ======== BASIC AUTH

export type BasicAuth = OAS2_BasicAuth | OAS3_BasicAuth

export interface OAS2_BasicAuth {
	type: 'basic'
	description?: string
}

export interface OAS3_BasicAuth {
	type: 'http'
	scheme: 'basic'
	description?: string
}

export interface StrictBasicAuthSecurity<T extends unknown> {
	security: BasicAuth
	handle: (username: string, password: string) => SecurityAgent<T>
	scopes: Scope<T>
	validScopes?: string[]
	validateScope?: ValidateScope
}

// ======== APIKEY AUTH

export interface ApiKeyAuth {
	type: 'apiKey'
	in: 'header' | 'query'
	name: string
	description?: string
}

export interface StrictApiKeySecurity<T extends unknown> {
	security: ApiKeyAuth
	handle: (apikey: string) => SecurityAgent<T>
	scopes: Scope<T>
	validScopes?: string[]
	validateScope?: ValidateScope
}

// ======== BEARER AUTH

export interface BearerAuth {
	type: 'http'
	scheme: 'bearer'
	description?: string
}

export interface StrictBearerSecurity<T extends unknown> {
	security: BearerAuth
	handle: (token: string) => SecurityAgent<T>
	scopes: Scope<T>
	validScopes?: string[]
	validateScope?: ValidateScope
}

// ======== OPENID AUTH

export interface OpenIdConnectAuth {
	type: 'openIdConnect'
	openIdConnectUrl: string
	description?: string
}

export interface StrictOpenIdConnectSecurity<T extends unknown> {
	security: OpenIdConnectAuth
	handle: (token: string) => SecurityAgent<T>
	scopes: Scope<T>
	validScopes?: string[]
	validateScope?: ValidateScope
}
