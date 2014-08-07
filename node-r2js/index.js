var net = require('net');
var http = require('http');
var process = require('child_process');

function remoteCmd(port, cmd, cb) {
	var msg = "";
	try {
		var client = new net.Socket();
		client.connect(port, "localhost", function() {
			});
		client.write (cmd+"\n");
		client.on('data', function(data) {
			msg += data; 
		});

		// Add a 'close' event handler for the client socket
		client.on('close', function() {
			if (cb) cb (msg);
		});
	} catch (e) {
		console.error (e);
	}
}

var host = "cloud.rada.re"

function httpCmd(port, cmd, cb) {
// TODO
	var options = {
		hostname: host,
		port: 80,
		path: '/cmd/'+cmd, // encode
		method: 'GET'
	};

	var text = "";
	var req = http.get('http://'+host+'/cmd/'+cmd, function (res) {
		console.log("Got response: " + res.statusCode);
		console.log ("===",res.output);
console.log ("===",res);
		text += res.output;
	}).on ("errro", function(res) {
		  console.log("Got response: " + res.statusCode);
	}).on("data",function(res) {
		text += res;
console.log ("===",res);
	});

	req.on('close', function(e) {
		console.log("closed");
		cb (text);
	});

	// write data to request body
	/*
	   req.write('data\n');
	   req.write('data\n');
	   req.end();
	 */
}

var r2node = {
	connect : function (uri, cb) {
			  // use http server uri /cmd/...
		  },
	launch : function(file, cb) {
			 var port = (4000+(Math.random()*4000))|0; // TODO must be random
			 var ls = process.spawn('r2', ["-nqc.:"+port, file]);
			 var running = false;
			 var r2 = {
				 cmd : function (s, cb2) {
					       //httpCmd(port, s, cb2);
					       remoteCmd (port, s, cb2);
				       },
				 quit: function() {
					       ls.kill ('SIGINT');
				       }
			 }
			 ls.stderr.on('data', function (data) {
				 if (!running) {
					 running = true;
					 cb (r2);
				 }
				 //console.log('stdout: ' + data);
			 });
			 ls.stdout.on('data', function (data) {
				 if (!running) {
					 running = true;
					 cb (r2);
				 }
				 //console.log('stderr: ' + data);
			 });
			 ls.on('error', function (code) {
				 running = false;
				 console.log('ERROR');
			 });
			 ls.on('close', function (code) {
				 running = false;
				 if (code != 0)
					 console.log('child process exited with code ' + code);
			 });
		 },
	listen: function(file, cb) {
			// TODO
		}
}

module.exports = r2node;

