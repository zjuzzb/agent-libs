var MAX_VIDEO_REQUESTS = 30000;

var http = require('http');
var sleep = require('sleep');

var j = 0;
var cnt = 0;

var options = {
  host: '127.0.0.1',
//  path: '/search.php',
  path: '/',
//  path: '/lo.scap',
//  port: 80,
//  agent:false
};

callback = function(response) {

  var str;

  //another chunk of data has been recieved, so append it to `str`
  response.on('data', function (chunk) {
//    str += chunk;
  });

  //the whole response has been recieved, so we just print it out here
  response.on('end', function () {
//    console.log(str);
  });

  cnt++;
  if(cnt % 500 == 0)
  {
    console.log(cnt.toString());  
  }
}

function req_loop()
{
  j++;
//  options.path = '/' + j.toString();
//  sleep.usleep(100);
//  http.request(options, callback).end();

  if(j < MAX_VIDEO_REQUESTS)
  {
    setTimeout(req_loop, 1);
  }
}

http.globalAgent.maxSockets = 400;
  req_loop()
