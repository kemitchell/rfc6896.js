var crypto = require('crypto')

// The minimum requirements of the RFC
var CIPHER = 'AES-128-CBC'
var CIPHER_KEY = crypto.randomBytes(16)
var HMAC = 'SHA1'
var HMAC_KEY = 'hmac_key'
var TID = CIPHER + '-' + HMAC
var MAX_AGE = 1

function encipher(argument, iv) {
  var cipher = crypto.createCipheriv(CIPHER, CIPHER_KEY, iv)
  cipher.update(argument)
  return cipher.final() }

function decipher(argument, iv) {
  var cipher = crypto.createDecipheriv(CIPHER, CIPHER_KEY, iv)
  cipher.update(argument)
  return cipher.final() }

function hmac(argument, iv) {
  var hmac = crypto.createHmac(HMAC, HMAC_KEY)
  hmac.update(argument)
  return hmac.digest() }

function random() {
  return crypto.randomBytes(16) }

var scs = require('./')(TID, encipher, decipher, hmac, MAX_AGE, random)

require('tape')('rfc6896', function(test) {
  test.plan(3)

  var plaintext = 'fee fi fo fum'
  var plaintextBuffer = new Buffer(plaintext, 'utf8')
  var initializationVector = random()

  test.ok(
    plaintextBuffer.equals(
      decipher(
        encipher(plaintextBuffer, initializationVector),
        initializationVector)),
    'cipher suite sanity check')

  test.ok(
    plaintextBuffer.equals(
      scs.inboundTransform(
        scs.outboundTransform(
          plaintextBuffer))),
    'plaintext round-trip')

  var cookieValue = scs.outboundTransform(plaintextBuffer)

  setTimeout(
    function() {
      test.throws(
        function() {
          scs.inboundTransform(cookieValue) },
        /expired/,
        'cookie expires after session_max_age') },
    MAX_AGE * 2 * 1000) })
