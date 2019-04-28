'use strict'

const functions = require('firebase-functions')

// metamask-auth
const Web3 = require('web3')
const speakeasy = require('speakeasy')
const secret = 'rNONHRni6BAk7y2TiKrv' // TODO : process.env.SECRET2FA
const web3 = new Web3(Web3.givenProvider || 'ws://localhost:8546', null, {})

// CORS Express middleware to enable CORS Requests.
const cors = require('cors')({ origin: true })

// Firebase Setup
const admin = require('firebase-admin')
const serviceAccount = require('./service-account.json')
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${process.env.GCLOUD_PROJECT}.firebaseio.com`
})

exports.auth = functions.https.onRequest((req, res) => {
  const handleError = (msg, error) => {
    console.error(msg, error)
    return res.sendStatus(500)
  }

  const handleResponse = (msg, status, body) => {
    console.log(msg, {
      Response: {
        Status: status,
        Body: body
      }
    })
    if (body) {
      return res.status(200).json(body)
    }
    return res.sendStatus(status)
  }

  try {
    return cors(req, res, async () => {
      if (req.method !== 'POST') {
        return handleResponse('post error', 403)
      }
      if (!req.body.message) {
        return handleResponse('message error', 400)
      }

      if (!web3.utils.isAddress(req.body.message.account)) {
        return handleResponse({ account: req.body.message.account }, 400)
      }

      const account = web3.utils.toChecksumAddress(req.body.message.account)
      const token = req.body.message.token
      const signature = req.body.signature
      if (!account || !token || !signature) {
        return handleResponse({ account, token, signature }, 400)
      }

      const _2fa = true // speakeasy.totp.verifyDelta({ secret, token, window: 2 })
      if (!_2fa) {
        return handleResponse({ account, token }, 401) // Invalid 2fa
      }

      const valid = account === web3.eth.accounts.recover(JSON.stringify({ account: req.body.message.account, token }), signature)
      if (!valid) {
        return handleResponse({ account, signature }, 401) // Invalid signature
      }

      // On success return the Firebase Custom Auth Token.
      const firebaseToken = await admin.auth().createCustomToken(account)
      return handleResponse('address', 200, { token: firebaseToken })
    })
  } catch (error) {
    return handleError('auth error', error)
  }
})
