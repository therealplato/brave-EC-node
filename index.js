// brave-ec index.js
var fs = require('fs');
var path = require('path');
var forge = require('node-forge');
var asn1 = forge.asn1;
var prime256v1_privkey_validator = require('./prime256v1_privkey_validator.js');
var prime256v1_pubkey_validator = require('./prime256v1_pubkey_validator.js');

// Create a new keypair
// Load keypair from file
// Load keypair from stdin
module.exports = (function(){
  var braveEC = {};

  braveEC.loadPemPrivFromFile = function(filename, callback){
    filename = path.normalize(process.cwd()+'/'+filename); 
    fs.readFile(filename, 'utf8', function(err, pem){
      if(err){ return callback(err) };
      braveEC._pemPrivToOutput(pem, function(err, output){
        if(err){ return callback(err) };
        callback(null, output);
      });
    });
  };

  braveEC.loadPemPubFromFile = function(filename, callback){
    filename = path.normalize(process.cwd()+'/'+filename); 
    fs.readFile(filename, 'utf8', function(err, pem){
      if(err){ 
        return callback(err) 
      };
      braveEC._pemPubToOutput(pem, function(err, output){
        if(err){ return callback(err) };
        callback(null, output);
      });
    });
  };

  braveEC.newKeypair = function(callback){
    require('child_process').exec('openssl ecparam -name prime256v1 -genkey',
    function (error, stdout, stderr) {
      if(error){ 
        console.log(stderr); 
        return callback(error) 
      };
      var ecFound = /-----BEGIN EC/.exec(stdout);
      if(!ecFound){ callback(new Error('Doesn\'t look like a key')); };
      var pem = stdout; 
      braveEC._pemPrivToOutput(pem, function(err, output){
        if(err){ return callback(err) };
        callback(null, output);
      });
    });
  };

  braveEC.genKeypair = braveEC.newKeypair;

  braveEC._pemPrivToOutput = function(pemPriv, callback){
    // Note: The pem fields store a PEM armored, base64 encoded, DER data
    // structure that contains the public and/or private keys.
    //
    // The hex fields are NOT DER data, they are the actual values of the public
    // and private keys, suitable for interfacing with
    // https://pypi.python.org/pypi/ecdsa
    var output = {
      priv: {
        pem: "",
        hex: "",
      },
      pub: {
        pem: "",
        hex: "",
      },
    };
    output.priv.pem = pemPriv;
    // PEM encode the pubkey for this keypair:
    // Todo - Don't regen public key every time?
    braveEC._genPubKey(pemPriv, function(err, pemPub){
      if(err){ return callback(err) };
      output.pub.pem = pemPub;
      try {
        // Validate and parse the DER structure encoded in the PEM data
        // This is necessary to get the key values out to hex encode them
        var keyBuffers = braveEC.ASNFromDERPriv(pemPriv);
        output.pub.hex = keyBuffers.pubKey.toString('hex');
        console.log('Generated pubkey of hex length '+output.pub.hex.length);
        output.priv.hex = keyBuffers.privKey.toString('hex');
        console.log('Generated privkey of hex length '+output.priv.hex.length);
      } catch(e){
        return callback(e);
      }
      return callback(null, output);
    });
  };

  braveEC._pemPubToOutput = function(pemPub, callback){
    var output = {
      pub: {
        pem: "",
        hex: "",
      },
    };
    var isPemPub = !!pemPub.match(/-----BEGIN PUBLIC KEY-----/);
    if(!isPemPub){ return callback('bad PEM pubkey') };
    output.pub.pem = pemPub;
    try {
      // Validate and parse the DER structure encoded in the PEM data
      // This is necessary to get the key values out to hex encode them
      var keyBuffer = braveEC.ASNFromDERPub(pemPub);
      output.pub.hex = keyBuffer.pubKey.toString('hex');
    } catch(e){
      return callback(e);
    }
    return callback(null, output);
  };

  // Expected input is a DER-encoded EC key, either in a Node Buffer, hex
  // encoded utf8 string, or PEM-armored utf8 string.
  // Run it through forge to validate structure, throw or return ASN object
  braveEC.ASNFromDERPriv = function(input){
    // see ./prime256v1_privkey_validator.js
    var binBuffer = braveEC._normalizeInput(input);
    var forgeBuffer = forge.util.createBuffer(binBuffer.toString('binary'));
    var forgeASN = asn1.fromDer(forgeBuffer);

    // Validate the DER structure
    var capture = {};  var errors = [];
    if( !asn1.validate(forgeASN, prime256v1_privkey_validator, capture, errors) ){
      console.log(asn1.prettyPrint(forgeASN));
      console.log(capture);  console.log(errors);
      throw 'This buffer is not a DER encoded ecKeypair.';
    } else {
      // We have named some capture values for fields of interest:
      var privKeyRaw = capture.privKey;
      var privKeyForgeBuffer = forge.util.createBuffer(privKeyRaw, 'raw');
      var privKeyBin = privKeyForgeBuffer.getBytes();

      var pubKeyRaw = capture.pubKey;
      var pubKeyForgeBuffer = forge.util.createBuffer(pubKeyRaw, 'raw');
      var pubKeyBin = pubKeyForgeBuffer.getBytes();

      return {
        pubKey: new Buffer(pubKeyBin, 'binary'),
        privKey: new Buffer(privKeyBin, 'binary')
      };
      // return [forgeASN, capture]; // forgeASN contains the entire DER
    };
  };

  braveEC.ASNFromDERPub = function(input){
    // see ./prime256v1_pubkey_validator.js
    var binBuffer = braveEC._normalizeInput(input); // strips PEM etc
    var forgeBuffer = forge.util.createBuffer(binBuffer.toString('binary'));
    var forgeASN = asn1.fromDer(forgeBuffer);

    // Validate the DER structure
    var capture = {};  var errors = [];
    if( !asn1.validate(forgeASN, prime256v1_pubkey_validator, capture, errors) ){
      console.log(asn1.prettyPrint(forgeASN));
      console.log(capture);  console.log(errors);
      throw 'This buffer is not a DER encoded ecKeypair.';
    } else {
      // We have named some capture values for fields of interest:
      var pubKeyRaw = capture.pubKey;
      var pubKeyForgeBuffer = forge.util.createBuffer(pubKeyRaw, 'raw');
      var pubKeyBin = pubKeyForgeBuffer.getBytes();

      return {
        pubKey: new Buffer(pubKeyBin, 'binary'),
      };
      // return [forgeASN, capture]; // forgeASN contains the entire DER
    };
  };
  
  // Take PEM armored private EC key and generate PEM pubkey
  braveEC._genPubKey = function(input, callback){
    var openssl = require('child_process')
    .spawn('openssl' ,['ec','-pubout', '-conv_form', 'compressed']);

    openssl.stdin.write(input, 'utf8', function(err){ 
      if(err){return callback(err)};
      openssl.stdin.end();
    });

    var pubKey = "";
    openssl.stdout.setEncoding('utf8');
    openssl.stdout.on('data', function(data){
      pubKey += data;
    });

    openssl.stdout.on('end', function(){
      var ecFound = /-----BEGIN PUBLIC KEY-----/.exec(pubKey);
      if(!ecFound){ callback(new Error('Output doesn\'t look like a EC public key')); };
      return callback(null, pubKey);
    });

    openssl.on('error', function(err){
      return callback(err);
    });
  };


  braveEC._stripPemArmor = function(input){
    var rxPemParam = 
      /-----BEGIN EC PARAMETERS-----([^-]*)-----END EC PARAMETERS-----/
      .exec(input);
    var rxPemPriv =  
      /-----BEGIN EC PRIVATE KEY-----([^-]*)-----END EC PRIVATE KEY-----/
      .exec(input);
    var rxPemPub =  
      /-----BEGIN PUBLIC KEY-----([^-]*)-----END PUBLIC KEY-----/
      .exec(input);
    if(!!rxPemPriv){
      var dirtyBase64 = rxPemPriv[1];
    } else if(!!rxPemPub){
      var dirtyBase64 = rxPemPub[1];
    } else {
      throw('_stripPemArmor called without an EC PUBLIC/PRIVATE KEY');
    };
    var base64 = dirtyBase64.replace(/[ \r\n\t]/g,'');
    return base64;
  };

  // normalize Buffer and hex/PEM string to binary buffer for node-forge
  braveEC._normalizeInput = function(input){
    var encoded = null;
    if(input instanceof Buffer){
      // DER encoded prime256v1 keypair?
      encoded = new Buffer(input.length);
      input.copy(encoded);
    } else if(typeof input === "string"){
      var isHex = !!(/^[0-9a-f]*$/.exec(input));
      var isPem = !!(/-----BEGIN/).exec(input);
      if(isPem){
        var stripped = braveEC._stripPemArmor(input);
        encoded = new Buffer(stripped, 'base64');
      } else if(isHex){
        encoded = new Buffer(input, 'hex');
      } else {
        throw('validating unrecognized string');
      };
    } else {
      throw('validating non Buffer or String');
    };
    var output = new Buffer(encoded.length, 'binary');
    encoded.copy(output);
    return output;
  };

  // Experimental:
  braveEC.loadPemPrivFromStdin = function(callback){
    process.stdout.write('\nPaste your PEM-encoded prime256v1 key, then EOF (^D on Unix, ^Z Enter on Windows):');
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    var pem = "";
    process.stdin.on('data', function(data){
      pem += data;
    });
    process.stdin.on('close', function(){
      //process.stdout.write('\nThanks. Validating key...');
      console.log('\nThanks. Validating key...');
      braveEC._pemPrivToOutput(pem, function(err, output){
        if(err){ 
          return callback(err);
        //process.stdout.write('\nKey did not pass validation. Double check it is contains a PEM-encoded, ASCII armored private key for EC prime256v1');
        };
        console.log('\nYour private key was valid. Here\'s your hex-encoded private key:');
        console.log(output.priv.hex)
        console.log('\nHere\'s your hex-encoded public key:');
        console.log(output.pub.hex)
        callback(null, output);
      });
    });
  };

  braveEC.cfg = function(cfg){
    braveEC._config = cfg;
  };

  braveEC.sign = function(date, uri, body, callback){
    if(!braveEC._config.clientPriv){ 
      return callback('Set the client private key with .cfg before signing');
    };
    var keyName = path.normalize(braveEC._config.clientPriv);
    console.log(keyName);
    var payload = [date, uri, body].join('\n');
    var sig = "";
    var openssl = require('child_process').spawn('openssl'
    ,['dgst', '-sign', keyName, '-sha256']);
    openssl.stdout.setEncoding('hex');
    openssl.stdout.on('data', function(data){ sig += data });
    openssl.on('close', function(){ callback(null, sig) });
    openssl.on('error', function(err){ callback(err) });
    openssl.stdin.write(payload);
    openssl.stdin.end();
  };

  return braveEC;
})();
