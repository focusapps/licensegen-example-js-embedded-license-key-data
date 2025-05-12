const {
  LICENSEGEN_PUBLIC_KEY,
  LICENSEGEN_PRODUCT_TOKEN,
  LICENSEGEN_ACCOUNT_ID,
  LICENSEGEN_POLICY_ID,
} = process.env

const fetch = require('node-fetch')
const crypto = require('crypto')
const chalk = require('chalk')

async function verifyPolicyScheme(policyId) {
  const res = await fetch(`https://licensegen-api.focusapps.app/v1/accounts/${LICENSEGEN_ACCOUNT_ID}/policies/${policyId}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${LICENSEGEN_PRODUCT_TOKEN}`,
      'Accept': 'application/vnd.api+json'
    }
  })
  const { data, errors } = await res.json()
  if (errors) {
    const msg = errors.map(e => `${res.status} ${e.title}: ${e.detail}`).join('\n')

    throw new Error(`Failed to retrieve policy!\n${msg}`)
  }

  return data.attributes.scheme === 'RSA_2048_PKCS1_PSS_SIGN_V2'
}

async function main() {
  const [_yarn, _start, cmd, ...argv] = process.argv

  // Sanity checks for environment vars
  if (!LICENSEGEN_PRODUCT_TOKEN) {
    throw new Error('Product API token is required')
  }

  if (!LICENSEGEN_ACCOUNT_ID) {
    throw new Error('Account ID is required')
  }

  if (!LICENSEGEN_POLICY_ID) {
    throw new Error('Policy ID is required')
  }

  if (!LICENSEGEN_PUBLIC_KEY) {
    throw new Error('Public key is required')
  }

  if (!LICENSEGEN_PUBLIC_KEY.includes(`-----BEGIN PUBLIC KEY-----`) ||
      !LICENSEGEN_PUBLIC_KEY.includes(`-----END PUBLIC KEY-----`)) {
    throw new Error(`Public key is not valid:\n${LICENSEGEN_PUBLIC_KEY}`)
  }

  switch (cmd) {
    case 'generate': {
      let key = null

      // Parse argument flags
      argv.forEach((arg, i, argv) => {
        switch (arg) {
          case '--data':
          case '-d':
            key = argv[i + 1]
            break
        }
      })

      if (!key) {
        throw new Error(`License key data is missing!`)
      }

      // Verify the policy is using the correct scheme
      const ok = await verifyPolicyScheme(LICENSEGEN_POLICY_ID)
      if (!ok) {
        throw new Error(`Policy ${LICENSEGEN_POLICY_ID} is not using RSA_2048_PKCS1_PSS_SIGN_V2 scheme!`)
      }

      // Generate a new license key
      const res = await fetch(`https://licensegen-api.focusapps.app/v1/accounts/${LICENSEGEN_ACCOUNT_ID}/licenses`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${LICENSEGEN_PRODUCT_TOKEN}`,
          'Content-Type': 'application/vnd.api+json',
          'Accept': 'application/vnd.api+json'
        },
        body: JSON.stringify({
          data: {
            type: 'licenses',
            attributes: {
              key
            },
            relationships: {
              policy: {
                data: { type: 'policies', id: LICENSEGEN_POLICY_ID }
              },
              // If you're associating the license with a specific user, uncomment this line
              // and provide their user ID:
              // user: {
              //   data: { type: 'users', id: userId }
              // }
            }
          }
        })
      })

      // Check if we received an error from the LicenseGen API
      const { data, errors } = await res.json()
      if (errors) {
        const msg = errors.map(e => `${res.status} ${e.title}: ${e.detail}`).join('\n')

        throw new Error(`Failed to generate license!\n${msg}`)
      }

      console.log(chalk.green(`License key successfully generated!`))
      console.log(chalk.gray(`Signed key: ${data.attributes.key}`))

      break
    }
    case 'verify': {
      let key = null

      // Parse argument flags
      argv.forEach((arg, i, argv) => {
        switch (arg) {
          case '--key':
          case '-k':
            key = argv[i + 1]
            break
        }
      })

      if (!key) {
        throw new Error(`License key is missing!`)
      }

      // Extract key and signature from the license key string
      const [signingData, encodedSig] = key.split('.')
      const [signingPrefix, encodedKey] = signingData.split('/')
      if (signingPrefix !== 'key') {
        throw new Error(`License key prefix is invalid: ${signingPrefix}!`)
      }

      // Decode the base64 encoded key
      const dec = Buffer.from(encodedKey, 'base64').toString()

      // Verify the signature of the key
      const verifier = crypto.createVerify('sha256')
      verifier.write(`key/${encodedKey}`)
      verifier.end()

      const ok = verifier.verify({ key: LICENSEGEN_PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, encodedSig, 'base64')
      if (ok) {
        console.log(chalk.green(`License key is cryptographically valid!`))
        console.log(chalk.gray(`Embedded data: ${dec}`))
      } else {
        console.error(chalk.red('License key is not valid!'))
      }

      break
    }
    default:
      throw new Error(`Invalid command: ${cmd}`)
  }
}

main().catch(err =>
  console.error(
    chalk.red(`Error! ${err.message}`)
  )
)