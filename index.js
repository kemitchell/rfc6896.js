var FRAMING_SYMBOL = '|'

function identity(argument) {
  return argument }

function Box() {
  return Array.prototype.slice.call(arguments).join(FRAMING_SYMBOL) }

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

function NOW() {
  return '' + Math.floor(Date.now() / 1000) }

module.exports = function(
    TID, Enc, Dec, HMAC, session_max_age, RAND, Comp, Uncomp) {

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
    eDATA = e(DATA)
    eATIME = e(ATIME)
    eTID = e(TID)
    eIV = e(IV)
    AUTHTAG = HMAC(Box(eDATA, eATIME, eTID, eIV))
    SCS_cookie_value = Box(eDATA, eATIME, eTID, eIV, e(AUTHTAG))
    return SCS_cookie_value }

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

  function is_available(tid_prime) {
    return tid_prime.equals(TID) }

  function inboundTransform(SCS_cookie_value) {
    var split, eDATA, eATIME, eTID, eIV, eAUTHTAG, tag
    var tid_prime, tag_prime, atime_prime, iv_prime, data_prime
    var state
    if (split = split_fields(SCS_cookie_value)) {
      eDATA = split.eDATA
      eATIME = split.eATIME
      eTID = split.eTID
      eIV = split.eIV
      eAUTHTAG = split.eAUTHTAG
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
