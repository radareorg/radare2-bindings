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


function httpCmd(uri, cmd, cb) {
	var text = "";
	var req = http.get(uri+cmd, function (res) {
		res.on("data",function(res) {
			text += res;
		});
	}).on ("error", function(res) {
		  console.log("Got response: " + res.statusCode);
	});
	req.on('close', function(e) {
		cb (text);
	});
}

function r2bind(file, cb, r2cmd) {
	var port = (file.indexOf("http") != -1)? file
		: (4000+(Math.random()*4000))|0; // TODO must be random
	var ls = process.spawn('r2', ["-qc.:"+port, file]);
	var running = false;
	var r2 = {
		cmd : function (s, cb2) { r2cmd (port, s, cb2); },
		quit: function() { ls.kill ('SIGINT'); }
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
}

var r2node = {
	// TODO
	// - listen()
	// - rap()
	connect : function (uri, cb) {
		r2bind (uri, cb, httpCmd);
	},
	launch : function (file, cb) {
		r2bind (file, cb, remoteCmd);
        },
	listen: function(file, cb) {
		// TODO
	}
}

module.exports = r2node;
