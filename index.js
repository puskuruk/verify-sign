/* eslint-disable */
const SafeBuffer = require('safe-buffer').Buffer

function verifySign(
  { message, publicKey, signature },
  algorithm = 'sha256',
  options = {}
) {
  try {
    let createVerify

    if (typeof window !== 'undefined') {
      createVerify = require('crypto-browserify').createVerify

      message = SafeBuffer.from(message)
      publicKey = SafeBuffer.from(publicKey)
      signature = SafeBuffer.from(signature)
    } else {
      createVerify = require('crypto').createVerify
      message = SafeBuffer.from(message)
      publicKey = SafeBuffer.from(publicKey)
      signature = SafeBuffer.from(signature)
    }

    const verify = createVerify(algorithm, options)
    verify.update(message)
    verify.end()

    const isVerified = verify.verify({ key: publicKey }, signature)
    return isVerified
  } catch (error) {
    return false
  }
}

module.exports = verifySign
