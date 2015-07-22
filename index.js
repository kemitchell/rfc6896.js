/* Copyright (c) 2015 by Kyle E. Mitchell
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX: ISC
 */

// Identity function for use in lieu of compression and decompression
// functions.
function identity(argument) {
  return argument }

// Framing
var FRAMING_SYMBOL = '|'

function Box() {
  return Array.prototype.slice.call(arguments).join(FRAMING_SYMBOL) }

function split_fields(input) {
  var split = input.split(FRAMING_SYMBOL)
  if (split.length === 5) {
    return {
      eDATA: split[0],
      eATIME: split[1],
      eTID: split[2],
      eIV: split[3],
      eAUTHTAG: split[4] } }
  else {
    return false } }

// Base64 Encoder
function e(argument) {
  var base64String = new Buffer(argument, 'utf8').toString('base64')
  var equalsIndex = base64String.indexOf('=')
  if (equalsIndex > -1) {
    base64String = base64String.slice(0, equalsIndex) }
  return base64String
    .replace(/\+/g, '-')
    .replace(/\//g, '_') }

// Base64 Decoder
function d(argument) {
  var string = argument
    .replace(/-/g, '+')
    .replace(/_/g, '/')
  var modulus = string.length % 4
  if (modulus === 2) {
    string += '==' }
  else if (modulus === 3) {
    string += '=' }
  else if (modulus !== 0) {
    throw new Error('Invalid base64 string') }
  return new Buffer(string, 'base64') }

// Seconds since epoch, as a decimal string.
// The RFC as released said hex, but errata corect to decimal.
function NOW() {
  return '' + Math.floor(Date.now() / 1000) }

module.exports = function(
    TID, Enc, Dec, HMAC, session_max_age, RAND, Comp, Uncomp) {

  // If no compression functions are provided, use the identity function.
  Comp = !!Comp ? Comp : identity
  Uncomp = !!Uncomp ? Uncomp : identity

  TID = new Buffer(TID, 'utf8')

  function outboundTransform(plain_text_cookie_value) {
    var SCS_cookie_value
    var DATA, ATIME, IV, AUTHTAG
    var eDATA, eATIME, eTID, eIV
    IV = RAND()
    ATIME = NOW()
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
    var state
    // If the split isn't ok, it returns false.
    if (split = split_fields(SCS_cookie_value)) {
      // Replicate the RFC's splice semantics.
      eDATA = split.eDATA
      eATIME = split.eATIME
      eTID = split.eTID
      eIV = split.eIV
      eAUTHTAG = split.eAUTHTAG
      // Frame split ends here. Back to the RFC.
      tid_prime = d(eTID)
      if (is_available(tid_prime)) {
        tag_prime = d(eAUTHTAG)
        tag = HMAC(Box(eDATA, eATIME, eTID, eIV))
        if (tag.equals(tag_prime)) {
          atime_prime = d(eATIME)
          if (NOW() - parseInt(atime_prime) <= session_max_age) {
            iv_prime = d(eIV)
            data_prime = d(eDATA)
            state = Uncomp(Dec(data_prime, iv_prime))
            return state }
          // Response to invalid cookies, including discarding PDU, is left to
          // client code.
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
