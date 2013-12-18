// node-forge validator function for a NIST prime256v1 elliptic curve keypair
// structure figured out by plato using
// https://github.com/digitalbazaar/forge#asn1
var forge = require('node-forge');
var asn1 = forge.asn1;

module.exports = {
  name: 'ecKeypair',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  captureAsn1: 'ecKeypair',
  value:[
    {
      name: 'unknownInt',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.INTEGER,
      constructed: false,
      capture: 'unknownInt',
    }, 
    {
      name: 'privKey',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OCTETSTRING,
      constructed: false,
      capture: 'privKey',
    }, 
    {
      name: 'curveConstruction',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: asn1.Type.NONE,
      constructed: true,
      captureAsn1: 'ASNcurve',
      value: [{
        name: 'curveIdentifier',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.OID,
        constructed: false,
        value: asn1.oidToDer('1.2.840.10045.3.1.7'), 
        capture: 'curveName',
      }],
    },
    {
      name: 'publicKeyConstruction',
      tagClass: asn1.Class.CONTEXT_SPECIFIC,
      type: asn1.Type.BOOLEAN,
      constructed: true,
      captureAsn1: 'ASNpubKey',
      value: [{
        name: 'publicKey',
        tagClass: asn1.Class.UNIVERSAL,
        type: asn1.Type.BITSTRING,
        constructed: false,
        capture: 'pubKey'
      }]
    },
  ]
};
