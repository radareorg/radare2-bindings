
var r2node = require ("./"); //r2node.js");
r2node.launch ("/bin/ls", function(r2) {
	r2.cmd ("pd 3", function (o) {
		console.log (o);
		r2.quit ()
	});
});
