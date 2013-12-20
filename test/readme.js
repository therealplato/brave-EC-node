var braveEC = require('../index.js');
var fs = require('fs');
var d = new Date();
var datestr = [d.getFullYear(), d.getMonth(), d.getDay()].join('-');
var filename = './fixtures/braveApp-'+datestr+'.pem';
describe('readme code:', function(){
  describe('.newKeypair', function(){
    it('should generate keys successfully', function(done){
      // Generate a keypair 
      braveEC.newKeypair(function(err, keys){
        if(err){ throw err };
        // Write it to disk for future signatures:
        if(fs.existsSync(filename)){ 
          throw new Error('Not overwriting existing file '+filename)
        };
        fs.writeFileSync(filename, keys.priv.pem
        ,{
          encoding:'utf8', 
          mode: parseInt("600", 8), // set mode user-only read/write
        });
        done();
      });
    });
  });
  describe('.loadPemFromFile', function(){
    it('should load keys successfully', function(done){
      // Load an existing keypair from disk:
      braveEC.loadPemFromFile(filename, function(err, keys){
        if(err){ throw err };
        console.log('\nSuccessfully loaded keys from '+filename);
        //console.log(keys);
        done();
      });
    });
  });
});

