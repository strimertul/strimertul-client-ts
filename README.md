# strimertül library for Typescript

Typescript library for talking to strimertül.

API docs coming soon(tm)

## Getting started

This client only works in platforms with a WebSocket client, such as the browser and [Deno](https://deno.land/). Node.js currently does not work.

### CDN - ES6 Module

A compiled version is available on this repo at `dist/strimertul.js` and through jsDeliver at the following URL: https://cdn.jsdelivr.net/gh/strimertul/strimertul-client-ts/dist/strimertul.js

For production uses you should use a fixed tag, like this:

```ts
import Strimertul from "https://cdn.jsdelivr.net/gh/strimertul/strimertul-client-ts@1.0.0/dist/strimertul.js"
```

This version is recommended if you are building OBS overlays as it's built with compatibility for Chrome 75 (the version that's used by OBS web view)

### NPM package
If you are using a bundler such as Webpack, Parcel or [Vite](https://vitejs.dev/), you can include this client in your project by downloading and importing [@strimertul/strimertul](https://www.npmjs.com/package/@strimertul/strimertul) like this:

```sh
npm i --save @strimertul/strimertul
```

### Deno module

This package is available as a Deno module through Deno's own hosting service as https://deno.land/x/strimertul

To use it, simply import it like this:

```ts
import { Strimertul } from "https://deno.land/x/strimertul@v1.0.0/mod.ts"
```

## LICENSE

strimertul library for Typescript is licensed under ISC, see `LICENSE` for more details.