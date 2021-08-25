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
	SecurityTypes,
	StrictSecurity,
} from './types'
import type { FastifyInstance, FastifyRequest } from 'fastify'

export { StrictBasicAuthSecurity, StrictApiKeySecurity } from './types'

const ERROR_LABEL = 'fastify-autosecurity'

interface FastifyAutosecurityOptions {
	dir?: string
}

interface PassedSecurity {
	passed: number[]
	values: Record<string, any>
}

declare module 'fastify' {
	interface FastifyRequest {
		security?: PassedSecurity
	}
}

export default fastifyPlugin<FastifyAutosecurityOptions>(
	async (
		fastify: FastifyInstance,
		options: FastifyAutosecurityOptions,
		next: CallableFunction
	) => {
		const { dir } = { ...options, dir: options.dir || './security' }

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

		const securities = await glob(`${dirPath}/[!_]*[!.test].{js,ts}`)
		const securityModules: Record<string, StrictSecurity<any>> = {}

		for (const security of securities) {
			const securityName = security
				.replace(dirPath + '/', '')
				.replace('.js', '')
				.replace('.ts', '')

			securityModules[securityName] = loadModule(
				securityName,
				security
			)(fastify)
		}

		fastify.addHook('preValidation', async (request, reply) => {
			// @ts-expect-error not annotated
			if (request.context.schema?.security === undefined) {
				return
			}

			// @ts-expect-error not annotated
			const securityGroups = request.context.schema?.security as Array<
				Record<string, string[]>
			>

			const setOfSecurity: Set<string> = new Set(
				securityGroups.flatMap((s) => Object.keys(s))
			)

			for (const security of setOfSecurity) {
				if (security in securityModules === false) {
					throw new Error(
						`[ERROR]: security ${security} is not defined in ${request.url}`
					)
				}
			}

			const solvedSecurity: Record<string, any> = {}

			for (const security of setOfSecurity) {
				const securityData = getSecurityData(
					securityModules[security].security,
					request
				)

				if (securityData !== undefined) {
					console.log({
						solvedSecurity,
						security,
						module: securityModules[security],
						securityData,
					})

					solvedSecurity[security] = await securityModules[
						security
					].handle.apply(
						null,
						// @ts-expect-error ts cannot figure out security data to apply
						Array.isArray(securityData) ? securityData : [securityData]
					)
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
				//  else {
				// 	console.log(`security ${securityGroupIndex} NOT passed`)
				// }
			}

			if (request.security.passed.length === 0) {
				if (
					Object.values(solvedSecurity).filter((v) => v !== undefined)
						.length === 0
				) {
					// 401 nessuna autorizzazione fornita
					reply.status(401)
					throw new Error('No Authorization provided')
				} else {
					// 403 nessuna autorizzazione fornita passa la validazione
					reply.status(403)
					throw new Error('No Authorization passed')
				}
			}
		})

		fastify.addHook('onReady', () => {
			if ('swagger' in fastify === false) {
				throw new Error(`Missing Peer Deps 'fastify-swagger'`)
			}

			// @ts-ignore injected by fastify-swagger
			const swagger = fastify.swagger()

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
		// case 'openIdConnect': return getOpenIdConnectSecurityData(security, request)
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
	const headerName = security.name

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

export * from './types'
