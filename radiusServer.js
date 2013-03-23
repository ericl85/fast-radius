var dgram = require("dgram");
var radius = require("./lib/radiusPacket.js")

var server = dgram.createSocket("udp4");

server.on('message', function(msg, rinfo) {
	var buffer = new Buffer(msg);
	
	var myPacket = radius.decode(buffer);
	console.log(myPacket);

});

server.bind(1812);

