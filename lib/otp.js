var crypto   = require('crypto')
  , shasum   = crypto.createHash('sha256')
;

module.exports = new OTP();

function OTP () {
	
}

OTP.prototype.getMessageTime = function() {
	var unixtime = Math.floor(Date.now()/1000);
	var timestep = 30;

	return Math.floor(unixtime / timestep);
};

OTP.prototype.hmac_sha1 = function(secret, text) {
	var buf = new Buffer(secret);
	var hmac = crypto.createHmac('sha1', buf);
	hmac.update(text);

	return hmac.digest('hex');
};

OTP.prototype.genOTP = function (secret, text) {
	var digits = 6;

	var hexText = ('0000000000000000' + text.toString(16)).slice(-16);
	var bufText = new Buffer(hexText, 'hex');

	var hashVal = this.hmac_sha1(secret, bufText);
	var hashBuf = new Buffer(hashVal, 'hex');

	var offset = hashBuf[hashBuf.length - 1] & 0xf;
	var sn =	(hashBuf[offset] & 0x7f) << 24 |
				(hashBuf[offset+1] & 0xff) << 16 | 
				(hashBuf[offset+2] & 0xff) << 8 |
				(hashBuf[offset+3] & 0xff);

	var result = sn % Math.pow(10, digits);
	result = ('00000000' + result).slice(-digits);

	return result;
};

OTP.prototype.getTOTP = function (secret) {
	var messagetime = this.getMessageTime();
	return this.genOTP(secret, messagetime);
};
