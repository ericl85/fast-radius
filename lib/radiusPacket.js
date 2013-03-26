var crypto = require("crypto");

exports.radiusCodeDictionary = [
	{ code: 1, assignment: "Access-Request" },
	{ code: 2, assignment: "Access-Accept" },
	{ code: 3, assignment: "Access-Reject" },
	{ code: 4, assignment: "Accounting-Request" }
];

exports.radiusAVPDictionary = [
	{ code: 1, assignment: "User-Name", type: "string" },
	{ code: 2, assignment: "User-Password", type: "secretstring" },
	{ code: 3, assignment: "CHAP-Password", type: "string" },
	{ code: 4, assignment: "NAS-IP-Address", type: "ipaddress"},
	{ code: 5, assignment: "NAS-Port", type: "integer" },
	{ code: 31, assignment: "Calling-Station-Id", type: "string" },
	{ code: 32, assignment: "NAS-Identifier", type: "string" },
        { code: 40, assignment: "Acct-Status-Type", type: "integer" },
	{ code: 41, assignment: "Acct-Delay-Time", type: "integer" },
	{ code: 44, assignment: "Acct-Session-Id", type: "hash" },
        { code: 46, assignment: "Acct-Session-Time", type: "integer" }
];

exports.RadiusPacket = 

  function() {
    this.type = 0;
    this.packetId = 0;
    this.length = 0;
    this.authenticator;
    this.attributes = [];

    // Method: getPassword
    // Description: Decrypts the password using the shared secret. See
    //              RFC 2865 for the algorithm. 
    // Accepts: The shared secret of the RADIUS server.
    // Returns: the decrypted password.
    this.getPassword = function(secret) {
      // Cycle through the attriutes to find the User-Password
      for(var i=0; i < this.attributes.length; i++) {
        if(this.attributes[i].attributeCode == 2) {
          var passwordEncrypted = this.attributes[i].value;
        }
      }
      if(typeof passwordEncrypted == 'undefined') {
        return '';
      }

      // Compute an md5 of the shared secret + the authenticator.
      // For the first 16 bits of the encrypted password.
      var secretHash = crypto.createHash('md5');
      secretHash.update(secret);
      secretHash.update(this.authenticator);
      
      var password = '';
      for(var i=0; i < (passwordEncrypted.length/16); i++) {
        var encryptedPasswordSegment = passwordEncrypted.slice(i*16, (i+1)*16);
        var passwordSegment = _xor(encryptedPasswordSegment, secretHash.digest());

        if(i < (passwordEncrypted.length/16)-1) {
          // If this isn't the last block of 16 characters, create a new hash
          secretHash = crypto.createHash('md5');
          secretHash.update(secret);
          secretHash.update(encryptedPasswordSegment);
        }
        password += passwordSegment.toString();
      }
      return password;
    }

    // Private function to return the logical XOR of the encrypted password and hash.
    function _xor(encryptedPassword, hash) {
      var xorBuffer = new Buffer(16);
      var passwordLength = 0;
      for(var i=0; i < 16; i++) {
        // If it's not a null character, xor it and add it to the buffer
        if(encryptedPassword.readUInt8(i) != 0) {
          passwordLength++;
          xorBuffer[i] = encryptedPassword.readUInt8(i) ^ hash.readUInt8(i);
        }
      }

      return xorBuffer.slice(0, passwordLength);
    }
  }

exports.RadiusAVP =

  function() {  
    this.attribute = 0;
    this.attributeCode = 0;
    this.length = 0;
    this.value;
  }

exports.decode =

  function(packetBuffer) {
    
    radiusPacket = new exports.RadiusPacket();
    radiusPacket.type = exports._codeType(packetBuffer.readUInt8(0));
    radiusPacket.packetId = packetBuffer.readUInt8(1);
    radiusPacket.length = packetBuffer.readUInt16BE(2);
    radiusPacket.authenticator = packetBuffer.slice(4, 20);
    var offset = 20;
    while(offset < packetBuffer.length) {
      var attributeLength = packetBuffer.readUInt8(offset+1);
      radiusPacket.attributes.push(exports._avp(packetBuffer.slice(offset, offset+attributeLength)));
      offset += attributeLength;
    }

    return radiusPacket;
  }

exports._codeType = 

  function(code) {
    for (var i=0; i<exports.radiusCodeDictionary.length; i++) {
      if(exports.radiusCodeDictionary[i].code == code) {
        return exports.radiusCodeDictionary[i].assignment;
      }
    }
    return "undefined type";
  }

exports._avpType = 

  function(code) {
    for(var i=0; i < exports.radiusAVPDictionary.length; i++) {
      if(exports.radiusAVPDictionary[i].code == code) {
        return exports.radiusAVPDictionary[i];
      }
    }
    return { code: 0, assignment: "undefined type", type: "string" };
  }

exports._avp = 

  function(buffer) {
    radiusAvp = new exports.RadiusAVP();
    
    // Read the first byte of the buffer and get the AVP Type from the dictionary
    var attribute = buffer.readUInt8(0);
    var avpType = exports._avpType(attribute);
    
    radiusAvp.attribute = avpType.assignment;
    radiusAvp.attributeCode = attribute;

    // Read the length
    radiusAvp.length = buffer.readUInt8(1);

    // Read the value depending on the AVP Type
    if(avpType.type == "string") {
      radiusAvp.value = buffer.slice(2, radiusAvp.length).toString();
    }
    else if(avpType.type == "hash") {
      radiusAvp.value = buffer.slice(2, radiusAvp.length).toString();
    }
    else if(avpType.type == "ipaddress") {
      radiusAvp.value = "";
      for(var i=0; i < 3; i++) {
        radiusAvp.value += buffer.readUInt8(i+2) + ".";
      }
      radiusAvp.value += buffer.readUInt8(5);
    }
    else if(avpType.type == "integer") {
      radiusAvp.value = buffer.readUInt32BE(2);
    }
    else if(avpType.type == "secretstring") {
      radiusAvp.value = buffer.slice(2, radiusAvp.length);
    }
    return radiusAvp;
  } 
