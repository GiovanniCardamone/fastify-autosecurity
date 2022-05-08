import fastifyPlugin from 'fastify-plugin'
import fs from 'fs'
import path from 'path'
import glob from 'glob-promise'
import {
	ApiKeyAuth,
	BasicAuth,
	BearerAuth,
	OAS2_SecurityType,
	OAS3_SecurityType,
	OpenIdConnectAuth,
	SecurityTypes,
	StrictSecurity,
} from './types'
import type { FastifyInstance, FastifyRequest } from 'fastify'
import { Unauthorized, Forbidden } from 'http-class'

export { StrictBasicAuthSecurity, StrictApiKeySecurity } from './types'

const ERROR_LABEL = 'fastify-autosecurity'

interface FastifyAutosecurityOptions {
	dir?: string
	overrides?: Record<string, (server: FastifyInstance) => StrictSecurity<any>>
}

interface PassedSecurity {
	passed: number[]
	values: Record<string, any>
}

interface RequestContext {
	schema?: {
		security?: Array<Record<string, string[]>>
	}
}

declare module 'fastify' {
	interface FastifyRequest {
		security?: PassedSecurity
		context: RequestContext
	}

	interface FastifySchema {
		security?: Array<Record<string, string[]>>
	}
}

export default fastifyPlugin<FastifyAutosecurityOptions>(
	async (
		fastify: FastifyInstance,
		options: FastifyAutosecurityOptions,
		next: CallableFunction
	) => {
		const { dir } = { ...options, dir: options.dir || './security' }
		const overrides = options.overrides || {}

		let dirPath: string

		if (path.isAbsolute(dir)) {
			dirPath = dir
		} else if (path.isAbsolute(process.argv[1])) {
			dirPath = path.join(process.argv[1], dir)
		} else {
			dirPath = path.join(process.cwd(), process.argv[1], dir)
		}

		if (!fs.existsSync(dirPath)) {
			return next(new Error(`${ERROR_LABEL} dir ${dirPath} does not exists`))
		}

		if (!fs.statSync(dirPath).isDirectory()) {
			return next(
				new Error(`${ERROR_LABEL} dir ${dirPath} must be a directory`)
			)
		}

		const securities = await glob(`${dirPath}/*.[t|j]s`)
		const securityModules: Record<string, StrictSecurity<any>> = {}

		for (const security of securities) {
			const securityName = security
				.replace(dirPath + '/', '')
				.replace('.js', '')
				.replace('.ts', '')

			securityModules[securityName] =
				securityName in overrides
					? overrides[securityName](fastify)
					: loadModule(securityName, security)(fastify)
		}

		fastify.addHook('onRoute', (route) => {
			if (route?.schema?.security) {
				for (const security of route.schema.security) {
					for (const [securityName, securityScopes] of Object.entries(
						security
					)) {
						if (securityName in securityModules === false) {
							throw new Error(
								`[ERROR]: security "${securityName}" is not defined in "${
									route.url
								}". available securities: [${Object.keys(securityModules).join(
									', '
								)}]`
							)
						}

						for (const securityScope of securityScopes) {
							if (
								securityModules[securityName].validScopes?.includes(
									securityScope
								) === false &&
								securityModules[securityName].validateScope?.(securityScope) ===
									false
							) {
								throw new Error(
									`[ERROR]: scope "${securityScope}" for security "${securityName}" is invalid "${route.url}".`
								)
							}
						}
					}
				}
			}
		})

		fastify.addHook('preValidation', async (request, reply) => {
			if (
				request.context.schema?.security === undefined ||
				request.context.schema?.security.length === 0
			) {
				return
			}

			// all security for route
			const securityGroups = request.context.schema?.security

			// set of security to call to avoid multiple
			const setOfSecurity: Set<string> = new Set(
				securityGroups.flatMap((s) => Object.keys(s))
			)

			// set of security solved
			const solvedSecurity: Record<string, any> = {}

			//solving security
			for (const security of setOfSecurity) {
				const securityData = getSecurityData(
					securityModules[security].security,
					request
				)

				if (securityData !== undefined) {
					try {
						// @ts-expect-error ts cannot figure out security data to apply
						// eslint-disable-next-line
						solvedSecurity[security] = await securityModules[
							security
						].handle.apply(
							securityModules[security],
							Array.isArray(securityData) ? securityData : [securityData]
						)
					} catch (e) {
						reply.status(500)
						throw e
					}
				}
			}

			request.security = {
				passed: [],
				values: solvedSecurity,
			}

			for (const securityGroupIndex in securityGroups) {
				const securityGroup = securityGroups[securityGroupIndex]
				//
				let passed = true
				for (const [name, scopes] of Object.entries(securityGroup)) {
					if (
						name in solvedSecurity === false ||
						solvedSecurity[name] === undefined ||
						(await securityModules[name].scopes(
							solvedSecurity[name],
							scopes
						)) === false
					) {
						passed = false
						break
					}
				}

				if (passed) {
					request.security.passed.push(Number(securityGroupIndex))
				}
			}

			if (request.security.passed.length === 0) {
				if (
					Object.values(solvedSecurity).filter((v) => v !== undefined)
						.length === 0
				) {
					// 401 nessuna autorizzazione fornita
					reply.status(401)
					throw new Unauthorized('no auth method provided', {
						key: 'error.jwt.missing',
					})
				} else {
					// 403 nessuna autorizzazione fornita passa la validazione
					reply.status(403)
					throw new Forbidden('no auth method with grants', {
						key: 'error.jwt.permission',
					})
				}
			}
		})

		fastify.addHook('onReady', async () => {
			if ('swagger' in fastify === false) {
				throw new Error('Missing Peer Deps "fastify-swagger"')
			}

			const securityDefinitions = Object.entries(securityModules).reduce(
				(acc, [name, sec]) => ({
					[name]: sec.security,
				}),
				{}
			)

			// @ts-expect-error injected by fastify-swagger
			const swagger = fastify.swagger({
				swagger: {
					securityDefinitions,
				},
			})

			let schemePtr: Record<string, SecurityTypes> | undefined = undefined

			if ('swagger' in swagger) {
				if ('securityDefinitions' in swagger === false) {
					swagger.securityDefinitions = {}
				}

				schemePtr = swagger.securityDefinitions as Record<
					string,
					OAS2_SecurityType
				>
			} else if ('openapi' in swagger) {
				if ('components' in swagger === false) {
					swagger.components = {}
				}

				if ('securitySchemes' in swagger === false) {
					swagger.components!.securitySchemes = {}
				}

				schemePtr = swagger.components!.securitySchemes as Record<
					string,
					OAS3_SecurityType
				>
			}

			if (schemePtr !== undefined) {
				Object.entries(securityModules).forEach(([name, security]) => {
					schemePtr![name] = security.security
				})
			}
		})

		return next()
	},
	{
		fastify: '3.x',
		name: 'fastify-autosecurity',
		dependencies: ['fastify-swagger'],
	}
)

function loadModule(
	name: string,
	path: string
): (instance: any) => StrictSecurity<any> {
	// eslint-disable-next-line
	const module = require(path)

	if (typeof module === 'function') {
		return module as (instance: any) => StrictSecurity<any>
	}

	if (
		typeof module === 'object' &&
		'default' in module &&
		typeof module.default === 'function'
	) {
		return module.default as (instance: any) => StrictSecurity<any>
	}

	throw new Error(
		`${ERROR_LABEL}: invalid security module definition (${name}) ${path}. Must export a function`
	)
}

function getSecurityData(security: SecurityTypes, request: FastifyRequest) {
	switch (security.type) {
		case 'http':
			return security.scheme === 'basic'
				? getBasicAuthSecurityData(security, request)
				: security.scheme === 'bearer'
				? getBearerAuthSecurityData(security, request)
				: invalidSecurity(security)

		case 'basic':
			return getBasicAuthSecurityData(security, request)

		case 'apiKey':
			return getApiKeySecurityData(security, request)
		// case 'oauth2': return getOAuth2SecurityData(security, request)
		case 'openIdConnect':
			return getOpenIdConnectSecurityData(security, request)
		default:
			invalidSecurity(security)
	}
}

function invalidSecurity(security: SecurityTypes): never {
	throw new Error(`Invalid security: ${security}`)
}

function getBasicAuthSecurityData(
	security: BasicAuth,
	request: FastifyRequest
) {
	return request.headers.authorization !== undefined &&
		request.headers.authorization.startsWith('Basic ')
		? Buffer.from(request.headers.authorization.split(' ')[1], 'base64')
				.toString('ascii')
				.split(':')
		: undefined
}

function getApiKeySecurityData(security: ApiKeyAuth, request: FastifyRequest) {
	const headerName = security.name.toLocaleLowerCase()

	return request.headers[headerName] !== undefined
		? [request.headers[headerName]]
		: undefined
}

function getBearerAuthSecurityData(
	security: BearerAuth,
	request: FastifyRequest
) {
	return request.headers.authorization !== undefined &&
		request.headers.authorization.startsWith('Bearer ')
		? request.headers.authorization.split(' ')[1]
		: undefined
}

function getOpenIdConnectSecurityData(
	security: OpenIdConnectAuth,
	request: FastifyRequest
) {
	return request.headers.authorization
}

export * from './types'
