const AWS = require('aws-sdk');
const async = require('async');
const encoder = require('./encoder');
if (typeof process.env.AWS_DEFAULT_REGION !== 'undefined') {
  AWS.config.update({region: process.env.AWS_DEFAULT_REGION});
}

function decrypt(options, key, done) {
  var params = {
    CiphertextBlob: encoder.decode(key)
  };

  if (typeof options.context !== 'undefined') {
    params.EncryptionContext = options.context
  };

  return new AWS.KMS().decrypt(params, done);
}

function split(stashes, decryptedKeys, done) {
  var result = stashes.map((stash, index) => {
    stash.keyPlaintext = new Buffer(32);
    stash.hmacPlaintext = new Buffer(32);
    decryptedKeys[index].Plaintext.copy(stash.keyPlaintext, 0, 0, 32);
    decryptedKeys[index].Plaintext.copy(stash.hmacPlaintext, 0, 32);
    return stash;
  });
  return done(null, result);
}

module.exports = {
  decrypt: (options, stashes, done) => {
    return async.waterfall([
      async.apply(async.map, stashes.map(s => s.key),
                  async.apply(decrypt, options)),
      async.apply(split, stashes)
    ], done);
  }
};
