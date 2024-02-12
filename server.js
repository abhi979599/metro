const express = require('express'); 
const bodyParser = require('body-parser'); 
const crypto = require('crypto'); 
const _sodium = require('libsodium-wrappers');
const axios = require('axios');
const _ = require('lodash');
const https = require('https');

const port = 3000; 
const PRIVATE_KEY_1 =
  'MC4CAQAwBQYDK2VuBCIEIAB75em8HtizzoKrlRfRiE5ee9cfouaoaouQt3g6orFH';
const PUBLIC_KEY_1 =
  'MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM=';
const REQUEST_ID = 'intileotech007';
const SIGNING_PRIVATE_KEY =
  '/yluOWfI3eFsoWr8PaA/7gE4uY3j7OHc09PtobFCRNcsVhw8GSZ4y9xf+vcHyfM/rhD/3Ejg9zJOmWSH7mLoag==';

const PUBLIC_KEY_2 ='LFYcPBkmeMvcX/r3B8nzP64Q/9xI4PcyTplkh+5i6Go=';

const htmlFile = `
<!--Contents of ondc-site-verification.html. -->
<!--Please replace SIGNED_UNIQUE_REQ_ID with an actual value-->
<html>
  <head>
    <meta
      name="ondc-site-verification"
      content="SIGNED_UNIQUE_REQ_ID"
    />
  </head>
  <body>
    ONDC Site Verification Page
  </body>
</html>
`;

const privateKey = crypto.createPrivateKey({
  key: Buffer.from(PRIVATE_KEY_1, 'base64'), 
  format: 'der',
  type: 'pkcs8', 
});
const publicKey = crypto.createPublicKey({
  key: Buffer.from(PUBLIC_KEY_1, 'base64'), 
  format: 'der', 
  type: 'spki', 
});

const sharedKey = crypto.diffieHellman({
  privateKey: privateKey,
  publicKey: publicKey,
});

var app = express();

app.use(bodyParser.json()); 

app.post('/ondc/on_subscribe', function (req, res) {
  const { challenge } = req.body; 
  const answer = decryptAES256ECB(sharedKey, challenge); 
  const resp = { answer: answer };
  res.status(200).json(resp);
});

app.get('/ondc-site-verification.html', async (req, res) => {
  const signedContent = await signMessage(REQUEST_ID, SIGNING_PRIVATE_KEY);
  const modifiedHTML = htmlFile.replace(/SIGNED_UNIQUE_REQ_ID/g, signedContent);
  res.send(modifiedHTML);
});

app.get('/', (req, res) => res.send('Hello World!'));

app.get('/subscribe_ondc', (req, res) => {

const uid = "intileotech007";
const timestamp = new Date().toISOString();

const jsonPayload = {
  context: {
    operation: {
      ops_no: 4
    }
  },
  message: {
    request_id: "intileotech007",
    timestamp: timestamp,
    entity: {
      gst: {
        legal_entity_name: 'Intileo Technologies LLP',
        business_address: 'Gurgaon',
        city_code: ['std:0124'],
        gst_no: '06AAHFI0291C1ZS'
      },
      pan: {
        name_as_per_pan: 'Intileo Technologies LLP',
        pan_no: 'AAHFI0291C',
        date_of_incorporation: '26/04/2018'
      },
      name_of_authorised_signatory: 'Ruchi Gupta',
      address_of_authorised_signatory: 'C 2518, Sushant Lok 1, Sector 43, Gurgaon 122002',
      email_id: 'himanshu@intileo.com',
      mobile_no: 8470058143,
      country: 'IND',
      subscriber_id: 'intileotech.com',
      unique_key_id: "intileotech007",
      callback_url: '/ondc',
      key_pair: {
        signing_public_key: 'LFYcPBkmeMvcX/r3B8nzP64Q/9xI4PcyTplkh+5i6Go=',
        encryption_public_key: 'MCowBQYDK2VuAyEAbf5XCRQh8hAfqty3U37RTW6Aer3W83Tn3s01pDlxl3I=',
        valid_from: '2023-12-02T13:44:54.101Z',
        valid_until: '2024-12-02T13:44:54.101Z'
      }
    },
    network_participant: [
      {
        subscriber_url: '/buyerAppl',
        domain: 'ONDC:RET10',
        type: 'buyerApp',
        msn: false,
        city_code: ['*']
      },
      {
        subscriber_url: '/buyerAppl',
        domain: 'ONDC:RET11',
        type: 'buyerApp',
        msn: false,
        city_code: ['*']
      },
      {
        subscriber_url: '/sellerAppl',
        domain: 'ONDC:RET11',
        type: 'sellerApp',
        msn: false,
        city_code: ['*']
      },
      {
        subscriber_url: '/sellerAppl',
        domain: 'ONDC:RET10',
        type: 'sellerApp',
        msn: false,
        city_code: ['*']
      },
    ]
  }
};

axios.post('https://staging.registry.ondc.org/subscribe', jsonPayload, {
  headers: {
    'Content-Type': 'application/json',
  }
})
  .then(response => {
        res.send(response.data);

  })
  .catch(error => {
    console.error(error);
  });


});

app.get('/health',async (req, res) => {
    $header='';
    const auth = await verifyHeader(jsonPayload);

});


function decryptAES256ECB(key, encrypted) {
  const iv = Buffer.alloc(0); 
  const decipher = crypto.createDecipheriv('aes-256-ecb', key, iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

async function signMessage(signingString, privateKey) {
  await _sodium.ready;
  const sodium = _sodium;
  const signedMessage = sodium.crypto_sign_detached(
    signingString,
    sodium.from_base64(privateKey, _sodium.base64_variants.ORIGINAL)
  );
  const signature = sodium.to_base64(
    signedMessage,
    _sodium.base64_variants.ORIGINAL
  );
  return signature;
}

const createAuthorizationHeader = async ({
    body,
    privateKey,
    subscriberId,
    subscriberUniqueKeyId,
    expires,
    created,
  }) => {
    const {
      signingString,
      expires: expiresT,
      created: createdT,
    } = await createSigningString({
      message: body,
      created,
      expires,
    });
  
    console.log('signingString'+signingString);

    const signature = await signMessage2({ signingString, privateKey });
  
    const header = `Signature keyId="${subscriberId}|${subscriberUniqueKeyId}|ed25519",algorithm="ed25519",created="${createdT}",expires="${expiresT}",headers="(created) (expires) digest",signature="${signature}"`;
    return header;
};

const createSigningString = async ({ message, created, expires }) => {

    console.log('message'+message);
    
    if (!created) created = Math.floor(new Date().getTime() / 1000).toString();
    if (!expires) expires = (parseInt(created, 10) + 1 * 60 * 60).toString();
  
    await _sodium.ready;
  
    const sodium = _sodium;
    const digest = sodium.crypto_generichash(64, sodium.from_string(message));
    const digestBase64 = sodium.to_base64(digest, _sodium.base64_variants.ORIGINAL);
  
    const signingString = `(created): ${created}
  (expires): ${expires}
  digest: BLAKE-512=${digestBase64}`;
  
    return { signingString, created, expires };
};

const signMessage2 = async ({ signingString, privateKey }) => {
    await _sodium.ready;
    const sodium = _sodium;
  
    const signedMessage = sodium.crypto_sign_detached(
      signingString,
      sodium.from_base64(privateKey, _sodium.base64_variants.ORIGINAL),
    );
    return sodium.to_base64(signedMessage, _sodium.base64_variants.ORIGINAL);
};
  
const executeAuthorization = async (jsonPayload) => {
    console.log('payload'+jsonPayload);
    const header = await createAuthorizationHeader({
      body: jsonPayload,
      privateKey: SIGNING_PRIVATE_KEY,
      bapId: "intileotech.com",
      bapUniqueKeyId: "intileotech007",
      subscriberId: 'intileotech.com',  
      subscriberUniqueKeyId: 'intileotech007',
    });
  
    return header;
};


const removeQuotes = (a) => {
    return a.replace(/^["'](.+(?=["']$))["']$/, '$1');
  };
  
  const splitAuthHeader = (authHeader) => {
    const header = authHeader.replace('Signature ', '');
    const re = /\s*([^=]+)=([^,]+)[,]?/g;
    let m;
    const parts = {};
    while ((m = re.exec(header)) !== null) {
      if (m) {
        parts[m[1]] = removeQuotes(m[2]);
      }
    }
    return parts;
  };
  
  const verifyMessage = async ({ signedString, signingString, publicKey }) => {
    try {
      await _sodium.ready;
      const sodium = _sodium;
      return sodium.crypto_sign_verify_detached(
        sodium.from_base64(signedString, _sodium.base64_variants.ORIGINAL),
        signingString,
        sodium.from_base64(publicKey, _sodium.base64_variants.ORIGINAL),
      );
    } catch (error) {
      return false;
    }
  };
  
  const verifyHeader = async ({ headerParts, body, publicKey }) => {
    const { signingString } = await createSigningString({
      message: body,
      created: headerParts.created,
      expires: headerParts.expires,
    });

    console.log('signingString'+signingString);


    const verified = await verifyMessage({
      signedString: headerParts.signature,
      signingString,
      publicKey,
    });
    return verified;
  };
  
  const isSignatureValid = async ({ header, body, publicKey }) => {
    try {
      const headerParts = splitAuthHeader(header);

      const keyIdSplit = headerParts.keyId.split('|');
      const subscriberId = keyIdSplit[0];
      const keyId = keyIdSplit[1];
  
      const isValid = await verifyHeader({ headerParts, body, publicKey });
      return isValid;
    } catch (error) {
      return error;
    }
   };

app.get('/search', async (req, res) => {

  const uid = "intileotech007";
  const timestamp = new Date().toISOString();
  
  const jsonPayload = {
    context: {
      domain: "ONDC:RET10",
      action: "search",
      country: "IND",
      city: "std:0124",
      core_version: "1.2.0",
      bap_id: "intileotech.com",
      bap_uri: "https://intileotech.com/ondc",
      transaction_id: "T89786r6781",
      message_id: "M109897867565443",
      timestamp: "2023-12-15T15:21:54.101Z",
      ttl: "PT30S"
    },
    message: {
      intent: {
          category: {
            id: 'Foodgrains',
          }
      },     
    }
  };
  

  const auth = await executeAuthorization(jsonPayload);

  const options = {
    hostname: 'staging.gateway.proteantech.in',
    path: '/search',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': auth
    }
  };

  const request = https.request(options, (response) => {
    let data = '';

    response.on('data', (chunk) => {
      data += chunk;
    });

    response.on('end', () => {
      console.log(data); 
    });
  });

  request.on('error', (error) => {
    console.error(error);
  });

  request.write(JSON.stringify(jsonPayload));
  request.end();
     
    
    });


app.get('/generate', async (req, res) => {

    const jsonPayload = {
        context: {
          domain: "ONDC:RET10",
          action: "search",
          country: "IND",
          city: "std:0124",
          core_version: "1.2.0",
          bap_id: "intileotech.com",
          bap_uri: "https://intileotech.com/ondc",
          transaction_id: "T89786r6781",
          message_id: "M109897867565443",
          timestamp: "2023-12-15T15:21:54.101Z",
          ttl: "PT30S"
        },
        message: {
          intent: {
              category: {
                id: 'Foodgrains',
              }
          },     
        }
      };
      
      const auth = await executeAuthorization(jsonPayload);

      res.send(auth);
      console.log(auth);

});

app.post('/validate', async (req, res) => {


     const {authHeader}=req.body;

    // const authHeader='Signature keyId="intileotech.com|intileotech007|ed25519",algorithm="ed25519",created="1702636531",expires="1702640131",headers="(created) (expires) digest",signature="u7qaTQPuKy7zyxNXtcSgVLbUuox/Zc/klrvgfjrfVfryiVOiyItQ6Tu776vP/3IFF6B/D0Qs+y0son2FXrAuAQ=="';

    console.log(authHeader);

    const headerParts = splitAuthHeader(authHeader);

      
    const keyIdSplit = headerParts.keyId.split('|');
    const subscriberId = keyIdSplit[0];
    const keyId = keyIdSplit[1];


    const body = {
        context: {
          domain: "ONDC:RET10",
          action: "search",
          country: "IND",
          city: "std:0124",
          core_version: "1.2.0",
          bap_id: "intileotech.com",
          bap_uri: "https://intileotech.com/ondc",
          transaction_id: "T89786r6781",
          message_id: "M109897867565443",
          timestamp: "2023-12-15T15:21:54.101Z",
          ttl: "PT30S"
        },
        message: {
          intent: {
              category: {
                id: 'Foodgrains',
              }
          },     
        }
      };

      const publicKey=PUBLIC_KEY_2;
      const isValid = await verifyHeader({ headerParts, body, publicKey });

        const { signingString } = await createSigningString({
      message: body,
      created: headerParts.created,
      expires: headerParts.expires,
    });

    console.log('signingString'+signingString);


    const verified = await verifyMessage({
      signedString: headerParts.signature,
      signingString,
      publicKey,
    });

    res.send(isValid);
    console.log(isValid);
        
});

app.listen(port,()=>{
    console.log(`server listening at port ${port}`)
})

 module.exports = app;
