import { AbstractValidationHandler, ValidationParams } from './validation-handler';
import * as rs from 'jsrsasign';

const cryptoSubtle = crypto.subtle;

/**
 * Allowed algorithms
 */
const allowedAlgorithms: string[] = [
  'HS256',
  'HS384',
  'HS512',
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'PS256',
  'PS384',
  'PS512'
];

/**
 * Time period in seconds the timestamp in the signature can
 * differ from the current time.
 */
const gracePeriodInSec = 600;

/**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
export class JwksValidationHandler extends AbstractValidationHandler {

  validateSignature(params: ValidationParams, retry = false): Promise<any> {
    const kid: string = params.idTokenHeader.kid;
    const keys: object[] = params.jwks.keys;
    let key: object;
    const decoder = new TextDecoder();

    const alg = params.idTokenHeader.alg;

    if (!params.idToken) {
      throw new Error('Parameter idToken expected!');
    }
    if (!params.idTokenHeader) {
      throw new Error('Parameter idTokenHandler expected.');
    }
    if (!params.jwks) {
      throw new Error('Parameter jwks expected!');
    }

    if (!params.jwks.keys || !Array.isArray(params.jwks.keys) || params.jwks.keys.length === 0) {
      throw new Error('Array keys in jwks missing!');
    }


    if (kid) {
      key = keys.find((k: any) => k.kid === kid /* && k['use'] === 'sig' */);
    } else {
      const kty = this.alg2kty(alg);
      const matchingKeys = keys.filter((k: any) => k.kty === kty && k.use === 'sig');

      if (matchingKeys.length > 1) {
        const error = 'More than one matching key found. Please specify a kid in the id_token header.';
        console.error(error);
        return Promise.reject(error);
      } else if (matchingKeys.length === 1) {
        key = matchingKeys[0];
      }
    }

    if (!key && !retry && params.loadKeys) {
      return params
        .loadKeys()
        .then(loadedKeys => (params.jwks = loadedKeys))
        .then(_ => this.validateSignature(params, true));
    }

    if (!key && retry && !kid) {
      const error = 'No matching key found.';
      console.error(error);
      return Promise.reject(error);
    }

    if (!key && retry && kid) {
      const error =
        'expected key not found in property jwks. ' +
        'This property is most likely loaded with the ' +
        'discovery document. ' +
        'Expected key id (kid): ' +
        kid;

      console.error(error);
      return Promise.reject(error);
    }

    const data = this.str2ab(params.idToken.split('.')[1]);
    const signature = this.str2ab(params.idToken.split('.')[2]);

    cryptoSubtle.importKey(
      'jwk',
      key,
      {
        name: 'RSA-PSS',
        hash: {
          name: 'SHA-256'
        }
      },
      true,
      ['verify']
    ).then(cryptoKey => {
      console.log(cryptoKey);

      cryptoSubtle.verify(   {
        name: 'RSA-PSS',
        hash: {
          name: 'SHA-256',
        },
        saltLength: 32,
      }, cryptoKey, signature, data).then(verified => {
        console.log(verified);
      });
    });

    const keyObj = rs.KEYUTIL.getKey(key);
    console.log('keyObj', keyObj);

    const validationOptions = {
      alg: allowedAlgorithms,
      gracePeriod: gracePeriodInSec
    };

    const isValid = rs.KJUR.jws.JWS.verifyJWT(
      params.idToken,
      keyObj,
      validationOptions
    );

    if (isValid) {
      return Promise.resolve();
    } else {
      return Promise.reject('Signature not valid');
    }
  }

  calcHash(valueToHash: string, algorithm: string): Promise<string> {
    const hashAlg = new rs.KJUR.crypto.MessageDigest({ alg: algorithm });
    const result = hashAlg.digestString(valueToHash);
    const result2 = this.str2ab(valueToHash);

    console.log(valueToHash);

    cryptoSubtle.digest(algorithm, result2).then(digested => {
      console.log('digested', digested);
    });

    console.log('result hashAlg', result);

    const byteArrayAsString = this.toByteArrayAsString(result);

    return Promise.resolve(byteArrayAsString);
  }

  toByteArrayAsString(hexString: string) {
    let result = '';
    for (let i = 0; i < hexString.length; i += 2) {
      const hexDigit = hexString.charAt(i) + hexString.charAt(i + 1);
      const num = parseInt(hexDigit, 16);
      result += String.fromCharCode(num);
    }
    return result;
  }

  private alg2kty(alg: string) {
    switch (alg.charAt(0)) {
      case 'R':
        return 'RSA';
      case 'E':
        return 'EC';
      default:
        throw new Error('Cannot infer kty from alg: ' + alg);
    }
  }

  ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf));
  }

  str2ab(str) {
    const buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
    const bufView = new Uint16Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
}
