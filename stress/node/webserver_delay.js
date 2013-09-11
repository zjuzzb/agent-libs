var http = require('http');
var fs = require('fs');
var sleep = require('sleep');

var j = 1;

http.globalAgent.maxSockets = 10;

http.createServer(function (req, res) {
	sleep.usleep(1000000);
//  setTimeout(function(){
    res.writeHead(400, {'Content-Type': 'text/plain'});
	res.end(j.toString());
	j++;
//  },2000);
}).listen(1234);
