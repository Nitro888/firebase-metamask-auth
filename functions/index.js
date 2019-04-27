/**
 * Copyright 2017 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for t`he specific language governing permissions and
 * limitations under the License.
 */
'use strict'

// metamask-auth
import { Accounts } from 'web3-eth-accounts'
const speakeasy = require('speakeasy')
const secret = 'rNONHRni6BAk7y2TiKrv'
const accounts = new Accounts()

const functions = require('firebase-functions')

// CORS Express middleware to enable CORS Requests.
const cors = require('cors')({ origin: true })

// Firebase Setup
const admin = require('firebase-admin')
const serviceAccount = require('./service-account.json')
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${process.env.GCLOUD_PROJECT}.firebaseio.com`
})

/**
 * Authenticate the provided credentials returning a Firebase custom auth token.
 * `address`, `token` and `signature` values are expected in the body of the request.
 * If authentication fails return a 401 response.
 * If the request is badly formed return a 400 response.
 * If the request method is unsupported (not POST) return a 403 response.
 * If an error occurs log the details and return a 500 response.
 */
exports.auth = functions.https.onRequest((req, res) => {
  const handleError = (address, error) => {
    console.error({ User: address }, error)
    return res.sendStatus(500)
  }

  const handleResponse = (address, status, body) => {
    console.log({ User: address }, {
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

  let address = ''
  try {
    return cors(req, res, async () => {
      // Authentication requests are POSTed, other requests are forbidden
      if (req.method !== 'POST') {
        return handleResponse(address, 403)
      }
      address = req.body.message.address
      if (!address) {
        return handleResponse(address, 400)
      }
      const token = req.body.message.token
      const sig = req.body.sig
      if (!token || !sig) {
        return handleResponse(address, 400)
      }

      const _2fa = speakeasy.totp.verifyDelta({ secret, token, window: 2 })
      if (!_2fa) {
        return handleResponse(address, 401) // Invalid 2fa
      }

      const valid = authenticate(req.body.message, sig)
      if (!valid) {
        return handleResponse(address, 401) // Invalid signature
      }

      // On success return the Firebase Custom Auth Token.
      const firebaseToken = await admin.auth().createCustomToken(address)
      return handleResponse(address, 200, { token: firebaseToken })
    })
  } catch (error) {
    return handleError(address, error)
  }
})

function authenticate (message, signature) {
  return message.address === accounts.recover(JSON.stringify(message), signature)
}
