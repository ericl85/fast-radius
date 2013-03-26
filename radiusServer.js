var dgram = require("dgram");
var radius = require("./lib/radiusPacket.js")

var server = dgram.createSocket("udp4");

server.on('message', function(msg, rinfo) {
	var buffer = new Buffer(msg);
	
	var myPacket = radius.decode(buffer);
	console.log(myPacket);
        console.log("Password is: " + myPacket.getPassword('secret'));

});

server.bind(1812);

