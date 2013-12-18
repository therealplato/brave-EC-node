brave-EC-node
=============

Elliptic Curve utilities for the [Brave Collective Core
Services](https://github.com/bravecollective/core) nodejs bindings

Requires openssl v0.9.8 or later, tested against openssl v1.0.1c and node v0.10.22

Validation and DER decoding are handled with
[node-forge](https://github.com/digitalbazaar/forge/)

##Usage

```
// $ npm install brave-EC; cd node_modules/brave-EC
// $ npm test

var d = new Date()l
var datestr = [d.getFullYear(), d.getMonth(), d.getDay()].join('-');
var filename = 'braveApp-'+datestr+'.pem';

var braveEC = require('brave-EC');

// Generate a keypair and write it to disk for future signatures:
braveEC.newECKeypair(function(err, keys){
  if(err){ throw err };
  if(fs.existsSync(filename)){ throw 'Not overwriting existing key' };
  fs.writeFileSync(filename, keys.priv.pem
  ,{
    encoding:'utf8', 
    mode: parseInt("600", 8), // set mode user-only read/write
  });
});

// Load an existing keypair from disk:
braveEC.loadECPemFromFile(filename, function(err, keys){
  if(err){ throw err };
  console.log('Successfully loaded these keys from '+filename;);
  console.log(keys);
});

/* This `keys` object returned by .newECKeypair and .loadECPemFromFile
will look like:
{ 
  priv: {
    hex: "a4ab...",
    pem: "-----BEGIN EC PARAMETERS...",
  },
  pub: {
    hex: "dead...",
    pem: "-----BEGIN EC PUBLIC...",
  },
}
*/                      

// Extract the private and public keys from a DER-encoded ASN.1 object:
var keys = braveEC._ecASNfromDER(input);

// `input` may be Node Buffer, utf8 hex string, or utf8 PEM-armored EC PRIVATE
// KEY string. 
// `keys` will have .privKey and .pubKey properties, these are nodejs binary
// buffers suitable for .toString(encoding) or writing to file
```

##Todo
Sign and verify

##Done
Decode DER to get actual keys
