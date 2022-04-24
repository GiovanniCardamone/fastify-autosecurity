import fastify from 'fastify'
import fastifyAutosecurity from '../src'

describe('fastify-autosecurity', () => {
	test('example test', () => {
		const server = fastify()

		server.register(fastifyAutosecurity, {
			dir: './fixtures/1',
		})

		expect(true).toBe(true)
	})
})
