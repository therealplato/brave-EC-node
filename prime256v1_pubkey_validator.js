// node-forge validator function for a NIST prime256v1 elliptic curve keypair
// structure figured out by plato using
// https://github.com/digitalbazaar/forge#asn1
var forge = require('node-forge');
var asn1 = forge.asn1;

module.exports = {
  name: 'ecPubkey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'ecPubkey',
  value:[
    {
      name: 'keyInfo',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.SEQUENCE,
      constructed: true,
      captureAsn1: 'ecPubkey',
      value: [
      {
        name: 'keyType',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        value: asn1.oidToDer('1.2.840.10045.2.1'),
        capture: 'keyType',
      },
      {
        name: 'curveIdentifier',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        value: asn1.oidToDer('1.2.840.10045.3.1.7'), 
        capture: 'curveName',
      },
      ],
    },
    {
      name: 'pubKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.BITSTRING,
      constructed: false,
      capture: 'pubKey',
    }, 
  ]
};
