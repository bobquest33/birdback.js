// PKCS#1 (OAEP) mask generation function
function oaep_mgf1_arr(seed, len) {
    var mask = '', i = 0;

    while (mask.length < len) {
        mask += rstr_sha1(String.fromCharCode.apply(String, seed.concat([
                (i & 0xff000000) >> 24,
                (i & 0x00ff0000) >> 16,
                (i & 0x0000ff00) >> 8,
                i & 0x000000ff])));
        i += 1;
    }

    return mask;
}

var SHA1_SIZE = 20;

// PKCS#1 (OAEP) pad input string s to n bytes, and return a bigint
function oaep_pad(s, n) {
    if (s.length + 2 * SHA1_SIZE + 2 > n) {
        alert("Message too long for RSA");
    }

    var PS = '', i;

    for (i = 0; i < n - s.length - 2 * SHA1_SIZE - 2; i += 1) {
        PS += '\x00';
    }

    var DB = rstr_sha1('') + PS + '\x01' + s,
        seed = new Array(SHA1_SIZE);
    new SecureRandom().nextBytes(seed);

    var dbMask = oaep_mgf1_arr(seed, DB.length),
        maskedDB = [];

    for (i = 0; i < DB.length; i += 1) {
        maskedDB[i] = DB.charCodeAt(i) ^ dbMask.charCodeAt(i);
    }

    var seedMask = oaep_mgf1_arr(maskedDB, seed.length),
        maskedSeed = [0];

    for (i = 0; i < seed.length; i += 1) {
        maskedSeed[i + 1] = seed[i] ^ seedMask.charCodeAt(i);
    }

    return new BigInteger(maskedSeed.concat(maskedDB));
}

function RSAEncrypt(text) {
    var m = oaep_pad(text, (this.n.bitLength()+7)>>3);
    if(m == null) return null;
    var c = this.doPublic(m);
    if(c == null) return null;
    var h = c.toString(16);
    if((h.length & 1) == 0) return h; else return "0" + h;
}

RSAKey.prototype.encrypt = RSAEncrypt;
