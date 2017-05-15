var http = require('http');
var fs = require('fs');
var sleep = require('sleep');

var j = 1;

http.globalAgent.maxSockets = 100;

http.createServer(function (req, res) {
//	sleep.usleep(20000);
//  setTimeout(function(){
	r = j;
	for(k = 0; k< 400000; k++) {
		r = r + k * j % 2700;
	}

    res.writeHead(400, {'Content-Type': 'text/plain'});
	res.end(j.toString());
	j++;
//  },2000);
}).listen(80);
