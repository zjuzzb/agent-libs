var http = require('http'),
    fileSystem = require('fs'),
    path = require('path');

http.globalAgent.maxSockets = 100;

function log(str) {
	fileSystem.writeFile("server.log", str + '\n', function(err) {
	    if(err) {
	        return console.log(err);
	    }
	});
}

function sendFile(req, res) {
    var filePath = '/bin/tar';
    var stat = fileSystem.statSync(filePath);

    res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': stat.size
    });

    var readStream = fileSystem.createReadStream(filePath);
    // We replaced all the event handlers with a simple call to readStream.pipe()
    readStream.pipe(res);
}

http.createServer(function (req, res) {
	if(req.url == '/catalog') {
		fileSystem.readFile('resources/catalog.json', 'utf8', function (err,data) {
		  if(err) {
			log('Error: cannot open file');
		    res.writeHead(500, {'Content-Type': 'application/json'});
			res.end('{"status": "FAIL", "reason": "Internal server error"}');
		  }
		});
	} else {
		log('Info: serving URL ' + req.url);
		sendFile(req, res);	
	}
}).listen(80);
