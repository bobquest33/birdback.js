/**
 * Initializes a new Birdback object.
 *
 * @param string key The public encryption key.
 */
var Birdback = function (key) {
    "use strict";
    var asn1;
    this.invalidKeyMessage = 'Invalid encryption key.';
    try {
        asn1 = ASN1.decode(b64toBA(key));
    } catch (e) {
        throw new Error(this.invalidKeyMessage);
    }
    this.rsa = this.buildKey(asn1);
};


/**
* Builds an RSAKey object from given ASN1.
*
* @param ASN1 asn1 The ASN1 object.
*/
Birdback.prototype.buildKey = function (asn1) {
    "use strict";
    var integers = this.extractIntegers(asn1),
        rsa;
    if (integers.length !== 2) {
        throw new Error(this.invalidKeyMessage);
    }
    rsa = new RSAKey();
    rsa.setPublic(integers[0], integers[1]);
    return rsa;
};


/**
* Extracts integers from asn1.
*
* @param ASN1 asn1 The ASN1 object.
*/
Birdback.prototype.extractIntegers = function (asn1) {
    "use strict";
    var parts = [],
        start,
        end,
        data,
        i;
    if (asn1.typeName() === "INTEGER") {
        start = asn1.posContent();
        end = asn1.posEnd();
        data = asn1.stream.hexDump(start, end).replace(/[ \n]/g, "");
        parts.push(data);
    }
    if (asn1.sub !== null) {
        for (i = 0; i < asn1.sub.length; i += 1) {
            parts = parts.concat(this.extractIntegers(asn1.sub[i]));
        }
    }
    return parts;
};

/**
 * Encrypts the given value.
 *
 * @param string value The value to encrypt.
 */
Birdback.prototype.encrypt = function (value) {
    "use strict";
    return this.rsa.encrypt(value);
};


Birdback.luhn = {};


/**
* Calculates Luhn value for given digits.
*
* @param string digits The digits.
*/
Birdback.luhn.calculate = function (digits) {
    "use strict";
    var sum = 0,
        i,
        delta = [0, 1, 2, 3, 4, -4, -3, -2, -1, 0],
        deltaIndex,
        deltaValue,
        mod10;
    for (i = 0; i < digits.length; i += 1) {
        sum += parseInt(digits.substring(i, i + 1), 10);
    }
    for (i = digits.length - 1; i >= 0; i -= 2) {
        deltaIndex = parseInt(digits.substring(i, i + 1), 10);
        deltaValue = delta[deltaIndex];
        sum += deltaValue;
    }
    mod10 = sum % 10;
    mod10 = 10 - mod10;
    if (mod10 === 10) {
        mod10 = 0;
    }
    return mod10;
};


/**
* Validates Luhn for given digits.
*
* @param string digits The digits.
*/
Birdback.luhn.validate = function (digits) {
    "use strict";
    var digit = parseInt(digits.substring(digits.length - 1, digits.length), 10),
        less = digits.substring(0, digits.length - 1);
    if (this.calculate(less) === parseInt(digit, 10)) {
        return true;
    }
    return false;
};