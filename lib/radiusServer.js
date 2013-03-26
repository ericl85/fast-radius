var radiusPackets = require("./radiusPacket.js")
var dgram = require("dgram");

exports.RadiusServer = function(authPort, acctPort) {

  this.clients = [{ name: 'The BOOBS', address: '172.27.10.139', secret: 'secret' }];
    
  this.authServer = dgram.createSocket("udp4");
  this.acctServer = dgram.createSocket("udp4");

  var theServer = this;

  this.onAccessRequest = function(packet, address, port) {
    console.log("Received authenticate request: " + packet);
  }

  this.onAccountingRequest = function(packet, address, port) {
    console.log("Received accounting request: " + packet);
  }

  this.authServer.on('message', function(msg, rinfo) {
    var buffer = new Buffer(msg);
    var authPacket = radiusPackets.decode(buffer);

    if(authPacket.type == 'Access-Request') {
      theServer.onAccessRequest(authPacket, rinfo.address, rinfo.port);
    }
  });

  this.acctServer.on('message', function(msg, rinfo) {
    var buffer = new Buffer(msg);
    var acctPacket = radiusPackets.decode(buffer);

    if(acctPacket.type == 'Accounting-Request') {
      theServer.onAccountingRequest(acctPacket, rinfo.address, rinfo.port);
    }
  });

  this.sendAuthResponse = function(address, port, original, response) {
    var client = this._getClient(address);
    var responseBuffer = response.finalize(original.authenticator, client.secret);
    this.authServer.send(responseBuffer,0, responseBuffer.length, port, address, function(err, bytes) {
      console.log("Sent " + response.type + " to " + address + ":" + port)
    });
  }

  this.sendAcctResponse = function(address, port, original, response) {
    var client = this._getClient(address);
    
    var responseBuffer = response.finalize(original.authenticator, client.secret);
    this.acctServer.send(responseBuffer,0, responseBuffer.length, port, address, function(err, bytes) {
      console.log("Sent " + response.type + " to " + address + ":" + port)
    });
  }

  this._getClient = function(address) {
    for(var i=0; i < this.clients.length; i++) {
      if(this.clients[i].address == address) {
        return this.clients[i];
      }
    }
  }

  this.authServer.bind(authPort);
  this.acctServer.bind(acctPort);
}

