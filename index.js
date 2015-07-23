// Copyright (c) 2015 by Kyle E. Mitchell
//
// Permission to use, copy, modify, and/or distribute this software for
// any purpose with or without fee is hereby granted, provided that
// the above copyright notice and this permission notice appear in all
// copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
// WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
// AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
// DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
// OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
// TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.
//
// SPDX: ISC

// Identity function for use in lieu of compression functions.
function identity(argument) {
  return argument }

// Framing
var FRAMING_SYMBOL = '|'

function Box() {
  return Array.prototype.slice.call(arguments).join(FRAMING_SYMBOL) }

function split_fields(input) {
  var split = input.split(FRAMING_SYMBOL)
  return ( split.length === 5 ? split : false ) }

// RFC 4648 URL-safe Base64
var base64 = require('urlsafe-base64')
var e = base64.encode
var d = base64.decode

// Seconds since epoch, as a decimal string.
// The RFC as released said hex, but errata corect to decimal.
function NOW() {
  return Math.floor(Date.now() / 1000) }

module.exports = function(
    TID, Enc, Dec, HMAC, session_max_age, RAND, Comp, Uncomp) {

  // If no compression functions provided, use the identity function.
  Comp = ( !!Comp ? Comp : identity )
  Uncomp = ( !!Uncomp ? Uncomp : identity )

  TID = new Buffer(TID, 'utf8')

  function outboundTransform(plain_text_cookie_value) {
    var SCS_cookie_value
    var DATA, ATIME, IV, AUTHTAG
    var eDATA, eATIME, eTID, eIV
    IV = RAND()
    ATIME = new Buffer(NOW().toString(), 'utf8')
    DATA = Enc(Comp(plain_text_cookie_value), IV)
    // Cache encoded values, rather than encode them twice.
    eDATA = e(DATA)
    eATIME = e(ATIME)
    eTID = e(TID)
    eIV = e(IV)
    // Caching ends here. Back to the RFC.
    AUTHTAG = HMAC(Box(eDATA, eATIME, eTID, eIV))
    SCS_cookie_value = Box(eDATA, eATIME, eTID, eIV, e(AUTHTAG))
    return SCS_cookie_value }

  function is_available(tid_prime) {
    return tid_prime.equals(TID) }

  function inboundTransform(SCS_cookie_value) {
    var split, eDATA, eATIME, eTID, eIV, eAUTHTAG, tag
    var tid_prime, tag_prime, atime_prime, iv_prime, data_prime
    var state, age
    // If the split isn't ok, it returns false.
    if (split = split_fields(SCS_cookie_value)) {
      // Replicate the RFC's splice semantics.
      eDATA = split[0]
      eATIME = split[1]
      eTID = split[2]
      eIV = split[3]
      eAUTHTAG = split[4]
      // Frame split ends here. Back to the RFC.
      tid_prime = d(eTID)
      if (is_available(tid_prime)) {
        tag_prime = d(eAUTHTAG)
        tag = HMAC(Box(eDATA, eATIME, eTID, eIV))
        if (tag.equals(tag_prime)) {
          atime_prime = d(eATIME)
          age = NOW() - parseInt(atime_prime.toString())
          if (age <= session_max_age) {
            iv_prime = d(eIV)
            data_prime = d(eDATA)
            state = Uncomp(Dec(data_prime, iv_prime))
            return state }
          // Response to invalid cookies, including discarding PDU, is
          // left to client code.
          else {
            throw new Error('expired') } }
        else {
          throw new Error('tag mismatch') } }
      else {
        throw new Error('TID not available') } }
    else {
      throw new Error('split not ok') } }

  return {
    outboundTransform: outboundTransform,
    inboundTransform: inboundTransform } }
