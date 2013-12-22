var assert = require("assert");
var fs = require('fs');

var FAKE_PEM = 
'-----BEGIN EC PARAMETERS-----\n'+
'BggqhkjOPQMBBw==\n'+
'-----END EC PARAMETERS-----\n'+
'-----BEGIN EC PRIVATE KEY-----\n'+
'qg==\n'+
'-----END EC PRIVATE KEY-----';

var REAL_PEM = "";

describe('openssl version', function(){
  var opensslV = "";
  it('should match /\d+\.\d+\.\d+/', function(done){

    require('child_process').exec('openssl version',
    function (error, stdout, stderr) {
      //console.log('stdout: ' + stdout);
      //console.log('stderr: ' + stderr);
      if (error !== null) {
        console.log();
      }
      assert.equal(error, null, 'exec error: ' + error);
      var vFound = /(\d+)\.(\d+)\.(\d+)/.exec(stdout);
      //console.log(stdout);
      assert.notEqual(vFound, null, "version string not found in stdout:"+stdout)
      if(vFound){ opensslV = vFound[0]; };
      done(null);
    });
  });

  it('should be greater than 0.9.8', function(){
    assert.notEqual("", opensslV);
    var good = require('semver').satisfies(opensslV, '>=0.9.8');
    assert.equal(good, true);
  });
});
describe('openssl ecparam -list_curves', function(){
  it('should match /prime256v1/', function(done){

    require('child_process').exec('openssl ecparam -list_curves',
    function (error, stdout, stderr) {
      assert.equal(error, null, "error was: "+error);
      var curveFound = /prime256v1/.exec(stdout);
      assert.notEqual(curveFound, null, "nist curve prime256v1 not found in stdout");
      done(null);
    });
  });
});

describe('keypair fixture', function(){
  it('should read from disk', function(){
    assert.doesNotThrow(function(){
      // Without the `encoding` option, fs.readFileSync returns buffer:
      REAL_PEM = fs.readFileSync('./fixtures/prime256v1-keypair.pem'
      , {encoding:'utf8'});
      assert.notEqual(null, REAL_PEM.match(/-----BEGIN EC/)
      , 'fixture pem doesn\'t look like a pem');
    });
  });
});

var braveEC = require('../index.js');
describe('braveEC', function(){
  it('should instantiate', function(){
    assert.notEqual(braveEC, undefined);
    assert.notEqual(braveEC.newKeypair, undefined);
  });

  describe('._normalizeInput', function(){
    it('should normalize Buffer to Buffer', function(){
      assert.doesNotThrow(function(){
        var input = new Buffer('aa', 'hex');
        var output = braveEC._normalizeInput(input);
        assert.equal(true, (output instanceof Buffer)
        , 'normalized to nonbuffer');
        assert.equal('aa', output.toString('hex'));
      });
    });
    it('should normalize hex encoded utf8 to Buffer', function(){
      assert.doesNotThrow(function(){
        var input = 'aa';
        var output = braveEC._normalizeInput(input);
        assert.equal(true, (output instanceof Buffer)
        , 'normalized to nonbuffer');
        assert.equal('aa', output.toString('hex'));
      });
    });
    it('should normalize PEM armored utf8 to Buffer', function(){
      assert.doesNotThrow(function(){
        var input = FAKE_PEM;
        var output = braveEC._normalizeInput(input);
        assert.equal(true, (output instanceof Buffer)
        , 'normalized to nonbuffer');
        assert.equal('aa', output.toString('hex'));
      });
    });
  });

  describe('._stripPemArmor', function(){
    it('should return the base64 encoded DER structure inside a PEM key'
    ,function(){
      assert.doesNotThrow(function(){
        var base64 = braveEC._stripPemArmor(FAKE_PEM);
        assert.equal(null, base64.match(/\n/), 'Newline found');
        var b64Buffer = new Buffer(base64, 'base64');
        assert.equal('aa', b64Buffer.toString('hex'));
      });
    });
  });
  
  describe('.ASNFromDERPriv', function(){
    it('should parse a DER Buffer into ASN object'
    ,function(){
      assert.doesNotThrow(function(){
        // make a DER buffer:
        var base64 = braveEC._stripPemArmor(REAL_PEM);
        var derBuffer = new Buffer(base64, 'base64');
        var asnResults = braveEC.ASNFromDERPriv(derBuffer);
        assert.equal(true, !!asnResults, 'asnResults missing');
        assert.notEqual(undefined, asnResults.privKey, 'privKey missing');
      });
    });
    it('should parse a PEM-armored string into ASN object', function(){
      assert.doesNotThrow(function(){
        var asnResults = braveEC.ASNFromDERPriv(REAL_PEM);
        assert.equal(true, !!asnResults, 'asnResults missing');
        assert.notEqual(undefined, asnResults.privKey, 'privKey missing');
      });
    });
    it('should parse a hex encoded DER object into ASN object', function(){
      assert.doesNotThrow(function(){
        var base64 = braveEC._stripPemArmor(REAL_PEM);
        var derBuffer = new Buffer(base64, 'base64');
        var hexStr = derBuffer.toString('hex')
        var asnResults = braveEC.ASNFromDERPriv(hexStr);
        assert.equal(true, !!asnResults, 'asnResults missing');
        assert.notEqual(undefined, asnResults.privKey, 'privKey missing');
      });
    });
  });

  describe('.ASNFromDERPub', function(){
    it('should load a PEM EC pubkey from file and validate it'
    , function(){
      var pubkey = fs.readFileSync('./fixtures/prime256v1-pubkey.pem', {encoding:'utf8'});
      assert.doesNotThrow(function(){
        var asnResults = braveEC.ASNFromDERPub(pubkey);
        assert.equal(true, !!asnResults, 'asnResults missing');
        assert.notEqual(undefined, asnResults.pubKey, 'pubKey missing');
      });

    });
  });

  describe('._genPubKey', function(){
    it('should convert utf8 PEM string to PEM pubkey with openssl'
    ,function(done){
      braveEC._genPubKey(REAL_PEM, function(err, pubPem){
        assert.equal(null, err);
        assert.notEqual(null, pubPem.match(/-----BEGIN PUBLIC KEY-----/));
        done();
      });
    });
  });
  
  describe('.newKeypair', function(){
    it('should create public and private keys in PEM and hex'
    ,function(done){
      braveEC.newKeypair(function(err, output){
        assert.equal(null, err);
        assert.notEqual(null, output.priv.hex.match(/^[0-9a-f]+$/));
        assert.notEqual(null, output.pub.hex.match(/^[0-9a-f]+$/));
        assert.notEqual(null, output.priv.pem.match(/-----BEGIN EC PRIVATE KEY-----/));
        assert.notEqual(null, output.pub.pem.match(/-----BEGIN PUBLIC KEY-----/));
        done();
      });
    });
  });

  describe('.loadPemPrivFromStdin', function(){
    it('should load a PEM from stdin and output hex keys to stdout'
    ,function(done){
      var output = "";
      // schedule "paste" to stdin
      setTimeout(
      function(){
        process.stdin.emit('data', REAL_PEM);
        process.stdin.end();
      }, 700);
      braveEC.loadPemPrivFromStdin(function(err, output){
        assert.equal(null, err);
        //console.log(output);
        assert.notEqual(output.pub.hex.match(/^[a-f0-9]+$/));
        done();
      });
    });
  });

  describe('.loadPemPrivFromFile', function(){
    it('should load a PEM from stdin and output hex keys'
    ,function(done){
      braveEC.loadPemPrivFromFile('./fixtures/prime256v1-keypair.pem'
      , function(err, output){
        assert.equal(null, err);
        assert.notEqual(output.pub.hex.match(/^[a-f0-9]+$/));
        done();
      });
    });
  });

  describe('loadPemPubFromFile', function(){
    it('should not error', function(done){
      braveEC.loadPemPubFromFile('./fixtures/clientPub132.pem', function(err, keys){
        assert.equal(err, null);
        console.log(keys);
        console.log('Hex key length', keys.pub.hex.length);
        done();
      });
    });
  });

});
