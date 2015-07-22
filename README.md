RFC 6896 (Secure Cookie Sessions) implementation for Node.js

A pair of transform functions. Takes your choice of cryptographic primitives. Hews closely to the language of the RFC.

Install:

```shellsession
$ npm install --save rfc6896
```

Then:

```javascript
var scs = require('rfc6896')

typeof scs.outboundTransform // => 'function'
// Takes a Buffer plaintext argument.

typeof scs.inboundTransform // => 'function'
// Takes a string cookie value argument.
```
