var dgram = require("dgram");
var radius = require("./lib/radiusServer.js")
var radiusPackets = require("./lib/radiusPacket.js")

var server = new radius.RadiusServer(1812, 1813);

server.onAccessRequest = function(packet, address, port) {
  var username = packet.getAttribute("User-Name").value;
  var password = packet.getPassword("secret");
  console.log("Username: " + username);
  console.log("Password: " + password);
  
  var replyPacket = radiusPackets.prepare("Access-Accept");
  replyPacket.addAttribute("Framed-IP-Address", "10.10.4.3");
  server.sendAuthResponse(address, port, packet, replyPacket);
}
