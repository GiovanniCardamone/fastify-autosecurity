# fastify-autosecurity

<div align="center">

![Logo](./logo.png)

![JavaScript](https://img.shields.io/badge/ES6-Supported-yellow.svg?style=for-the-badge&logo=JavaScript) &nbsp; ![TypeScript](https://img.shields.io/badge/TypeScript-Supported-blue.svg?style=for-the-badge)

[![NPM version](https://img.shields.io/npm/v/fastify-autosecurity.svg?style=flat)](https://www.npmjs.com/package/fastify-autosecurity)
[![NPM downloads](https://img.shields.io/npm/dm/fastify-autosecurity.svg?style=flat)](https://www.npmjs.com/package/fastify-autosecurity)
[![Known Vulnerabilities](https://snyk.io/test/github/GiovanniCardamone/fastify-autosecurity/badge.svg)](https://snyk.io/test/github/GiovanniCardamone/fastify-autosecurity)
[![GitHub license](https://img.shields.io/github/license/GiovanniCardamone/fastify-autosecurity.svg)](https://github.com/GiovanniCardamone/fastify-autosecurity/blob/master/LICENSE)

![CI](https://github.com/GiovanniCardamone/fastify-autosecurity/workflows/CI/badge.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/GiovanniCardamone/fastify-autosecurity/badge.svg?branch=master)](https://coveralls.io/github/GiovanniCardamone/fastify-autosecurity?branch=master)

</div>

> :star: Thanks to everyone who has starred the project, it means a lot!

plugin to handle securities in fastify automatically based on file name.

## :newspaper: **[Full Documentation](https://giovannicardamone.github.io/fastify-autosecurity/)**

[fastify-autosecurity](https://giovannicardamone.github.io/fastify-autosecurity/)

## :rocket: Install

```sh
npm install --save fastify-autosecurity
```

## :blue_book: Usage

### Register plugin

```js
const fastify = require('fastify')
const server = fastify()

server.register(require('fastify-autosecurity'), {
  dir: './<autosecurity-directory>', // relative to your cwd
})
```

### Create file in autosecurity directory

```js
//file: `<autosecurity-directory>/some/route.js`
//url:  `http://your-host/some/route`

export default (fastifyInstance) => ({
  security: {
    type: 'basic,
  },
  handle: async (token) => {
    return { user: 'my user id from token', whatever: 'something else i got from my application', scopes: ['user-basic', 'admin'] }
  },
  validScopes: ['user-basic', 'manager', 'consultant', 'admin'],
  scopes: async (myUser, scopesOfRote) => {
    return true // your logic to check scopes of user against scopes required in route
  }
})
```

### Using typescript support for module

```typescript
//file: `<autosecurity-directory>/some/route.ts`
//url:  `http://your-host/some/route`

import { FastifyInstance } from 'fastify'


interface MyUser {
  user: string
  whatever: string
  scopes: string[]
}

export default (fastify: FastifyInstance): StrictBasicAuthSecurity<MyUser> => ({
  security: {
    type: 'basic,
  },
  handle: async (token: string) => {
    return { user: 'my user id from token', whatever: 'something else i got from my application', scopes: ['user-basic', 'admin'] }
  },
  validScopes: ['user-basic', 'manager', 'consultant', 'admin'],
  scopes: async (myUser: MyUser, scopesOfRote: string[]) => {
    return true // your logic to check scopes of user against scopes required in route
  }
})
```

## :page_facing_up: License

Licensed under [MIT](./LICENSE)

## :sparkles: Contributors

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->

<!-- markdownlint-enable -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification.

Contributions of any kind welcome!
