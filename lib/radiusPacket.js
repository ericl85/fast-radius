exports.RadiusPacket = 

  function() {

    this.type = 0;
    this.packetId = 0;
    this.length = 0;
    this.authenticator;
    this.attributes = [];

    this.radiusCodes = ["undefined type", "Access-Request", "Access-Accept", "Access-Reject", "Accounting-Request", "Accounting-Response"];
    
    this.RadiusPacketType = function() {
	return this.radiusCodes[this.type];
    }
  }

exports.decode =

  function(packetBuffer) {
    
    radiusPacket = new exports.RadiusPacket();
    radiusPacket.type = packetBuffer.readUInt8(0);
    radiusPacket.packetId = packetBuffer.readUInt8(1);
    radiusPacket.length = packetBuffer.readUInt16BE(2);
    radiusPacket.authenticator = packetBuffer.slice(4, 19);
    var offset = 20;
    while(offset < packetBuffer.length) {
      var attributeLength = packetBuffer.readUInt8(offset+1);
      radiusPacket.attributes.push(exports.ParseAVP(packetBuffer.slice(offset, offset+attributeLength)));
      offset += attributeLength;
    }

    return radiusPacket;
  }

exports.RadiusAVP =

  function() {
    
    this.attribute = 0;
    this.length = 0;
    this.value;

    this.avpCodes = ["undefined type", "User-Password"];


    this.AVPType = function() {
      if(this.attribute == 1) {
        return "User-Password";
      }
      else {
        return "unknown type";
      }
    }
  }

exports.ParseAVP = 

    function(buffer) {
      radiusAvp = new exports.RadiusAVP();
      radiusAvp.attribute = buffer.readUInt8(0);
      radiusAvp.length = buffer.readUInt8(1);
      radiusAvp.value = buffer.slice(2, radiusAvp.length);
      return radiusAvp;
    }
      
