using Radare;

void main() {
	string code = """
print "Hello World\\n";
"""
;
	RLang lang = new RLang ();
	lang.use ("perl");
	lang.list (0);
	lang.run (code, (int)code.length);
}
