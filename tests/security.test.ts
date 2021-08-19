import fastify from 'fastify'
import autosecurity from '../src'
import tap from 'tap'

tap.test('tests not an option rn', { saveFixture: false }, (t) => {
	const server = fastify()

	server.register(autosecurity)

	server.listen(9000, () => {})

	t.end()
})
