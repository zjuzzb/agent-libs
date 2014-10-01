var http = require('http');
var j = 0;
var cnt = 0;

//The url we want is: 'www.random.org/integers/?num=1&min=1&max=10&col=1&base=10&format=plain&rnd=new'
var options = {
  host: '127.0.0.1',
  path: '/',
  port: 80,
  agent:false
};

callback = function(response) {

  var str;

  //another chunk of data has been recieved, so append it to `str`
  response.on('data', function (chunk) {
    str += chunk;
  });

  //the whole response has been recieved, so we just print it out here
  response.on('end', function () {
//    console.log(str);
  });

  cnt++;
  console.log(cnt.toString());  
}

function req_loop()
{
  j++;
  options.path = '/' + j.toString();
  http.request(options, callback).end();
  setTimeout(req_loop, 100);
}

http.globalAgent.maxSockets = 20;
req_loop()