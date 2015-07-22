RFC 6896 Secure Cookie Sessions for Node.js

A pair of transform functions. Takes your choice of cryptographic primitives. Hews closely to the language of the RFC.

Install:

```shellsession
$ npm install --save rfc6896
```

Then:

```javascript
var scs = require('rfc6896')(
	tid, // string
	encipher, // function(x, iv)
	decipher, // function(x, iv)
	hmac, // function(x)
	session_max_age, // seconds
	random, // function()
	compress, // function(x)
	decompress // function(x)
)

typeof scs.outboundTransform // => 'function'
// Takes a Buffer plaintext argument.

typeof scs.inboundTransform // => 'function'
// Takes a string cookie value argument.
// Throws exceptions.
```

Neither transform function references `this`.
