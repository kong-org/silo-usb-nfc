const crypto = require('crypto');
const elliptic = require('elliptic').ec;

const helpers = {

    _delay: function(ms) {

       return new Promise(function(resolve) {
           setTimeout(resolve,ms)
       });

    },
    _bytesToHex(byteArray) {

        return Array.from(byteArray, function(byte) {

            return ('0' + (byte & 0xFF).toString(16)).slice(-2);

        }).join('')

    },
    _hexToBytes: function(hex) {

        for (var bytes = [], c = 0; c < hex.length; c += 2) {
            bytes.push(parseInt(hex.substr(c, 2), 16));
        }
        return bytes;

    },
    _hexToAscii(hex) {

        var str = '';
        for (var n = 0; n < hex.length; n += 2) {
            str += String.fromCharCode(parseInt(hex.substr(n, 2), 16));
        }
        return str;

     },
    _capitalizeFirstLetter: function(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    },
    _verifySignature: function(msgHash, publicKeyLong, signatureLong) {

        // console.log(`BEGIN SIGNATURE VERIFICATION (in ms): ${Date.now()}`)

        // Return false if format of variables is unexpected.
        if (msgHash.length != 66 && msgHash.length != 64) {return false};
        if (signatureLong.length != 128) {return false};
        if (publicKeyLong.length != 130 && publicKeyLong.length != 128) {return false};

        // Remove leading '0x' in msgHash.
        if (msgHash.length == 66 && msgHash.slice(0, 2) == '0x') {
            msgHash = msgHash.slice(2);
        };

        // Remove leading '04' in publicKey.
        if (publicKeyLong.length == 130 && publicKeyLong.slice(0, 2) == '04') {
            publicKeyLong = publicKeyLong.slice(2);
        };

        // Reformat key and signature so elliptic package can handle them.
        var pub = {
            x: publicKeyLong.slice(0, publicKeyLong.length/2),
            y: publicKeyLong.slice(publicKeyLong.length/2)
        };

        var curveP256 = new elliptic('p256');
        var key = curveP256.keyFromPublic(pub, 'hex');

        // Reformat signature to one of several acceptable formats: {r :r , s: s}
        var signature = {
            r: signatureLong.slice(0, signatureLong.length/2),
            s: signatureLong.slice(signatureLong.length/2)
        };

        // Verify.
        var verified = key.verify(msgHash, signature);
        // console.log(`END SIGNATURE VERIFICATION (in ms): ${Date.now()}`)

        return verified;
    }
}

module.exports = {
  helpers, crypto, elliptic
}; 