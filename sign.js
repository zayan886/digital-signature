const crypto = require('crypto');
const fs = require('fs');

// import public and private key files
const publicKey = fs.readFileSync('private.pem', 'utf8'); // Note: this file actually contains the public key
const privateKey = fs.readFileSync('public.pem', 'utf8'); // Note: this file actually contains the private key

// create a variable sourceData and assign a value (random string)
const sourceData = "This is a random string data!";
const dataToEncrypt = sourceData;

// identify and call the method to encrypt using private key and create a variable encryptedData to hold the encrypted value
const encryptedData = crypto.privateEncrypt(privateKey, Buffer.from(dataToEncrypt, 'utf8'));

// identify and call the method to decrypt using public key and create a variable decryptedData to hold the decrypted value.
const decryptedData = crypto.publicDecrypt(publicKey, encryptedData);

// print the values of dataToEncrypt, encryptedData and decryptedData
console.log("dataToEncrypt:\n", dataToEncrypt);
console.log("\nencryptedData (Base64):\n", encryptedData.toString('base64'));
console.log("\ndecryptedData:\n", decryptedData.toString('utf8'));

function createDigSig(sourceData, privateKey) {
  // calculate the Hash of the sourceData (use SHA1 algo)
  const hash = crypto.createHash('sha1').update(sourceData).digest();
  
  // encrypt the hash with privatekey to get digital signature
  const digitalSignature = crypto.privateEncrypt(privateKey, hash);
  
  // return the digital signature (use base64 for decoding)
  return digitalSignature.toString('base64');
}

const signature = createDigSig(sourceData, privateKey);
console.log("\nDigital Signature (Base64):\n", signature);

function verifySign(signature, publicKey, sourceData) {
    // decrypt the signature
    const signatureBuffer = Buffer.from(signature, 'base64');
    const decryptedHashBuffer = crypto.publicDecrypt(publicKey, signatureBuffer);
    
    // calculate the hash value of the source data (use SHA1 algo)
    const calculatedHashBuffer = crypto.createHash('sha1').update(sourceData).digest();
    
    // check if decrypted data and hash value are same
    // return true if same else false
    return decryptedHashBuffer.equals(calculatedHashBuffer);
}

const isValid = verifySign(signature, publicKey, sourceData);
console.log("\nIs the signature valid?", isValid);

