/* radare2 - MIT - Copyright 2016 pancake */

using System;
using System.Collections;
using System.Collections.Generic;
using Mono.CSharp;
using Newtonsoft.Json;

class R2Repl {
	Evaluator e;
	CSharpShell shell = null;
	Hashtable argFlags;

	public static void Main(string[] args) {
		var repl = new R2Repl (args);
		repl.Run();
	}

	private bool RunArgs() {
		bool Result = true;
		if (argFlags.Contains("-e")) {
			foreach (string str in (List<string>)argFlags["-e"]) {
				this.e.Run(str);
			}
		}
		if (argFlags.Contains("-i")) {
			foreach (string str in (List<string>)argFlags["-i"]) {
				string text = System.IO.File.ReadAllText(str);
				this.e.Run(text);
				Result = false;
			}
		}
		return Result;
	}

	private void ShowHelp() {
		Console.WriteLine(@"
Usage: r2repl.exe [-i script.cs] [-e csharp-expression] [file-to-open-in-r2]
		");
	}

	private string[] ParseArgs(string[] args) {
		var newArg = new List<string>();
		argFlags = new Hashtable();
		string mode = null;
		foreach (string arg in args) {
			switch (arg) {
			case "-h":
				ShowHelp();
				return null;
			case "-e":
			case "-i":
				mode = arg;
				break;
			default:
				if (mode != null) {
					if (!argFlags.Contains(mode)) {
						argFlags[mode] = new List<string>();
					}
					((List<string>)argFlags[mode]).Add(arg);
					mode = null;
				} else {
					newArg.Add(arg);
				}
				break;
			}
		}
		return newArg.ToArray();
	}

	public R2Repl(string[] args) {
		this.e = new Evaluator(new CompilerContext(
				new CompilerSettings {
				WarningLevel = 0,
				ShowFullPaths = true
			}, new ConsoleReportPrinter()));

		e.Run("LoadAssembly(\"Mono.Posix\")");
		e.Run("LoadAssembly(\"r2pipe\")");
		e.Run("LoadAssembly(\"Newtonsoft.Json\")");
		e.Run("using System;");
		e.Run("using System.Collections;");
		e.Run("using System.Collections.Generic;");
		e.Run("using Mono.Unix;");
		e.Run("using Newtonsoft.Json;");

		e.Run(@"
/* example */
public class Opcode {
	public string opcode;
	public string family;
	public string type;
	public string esil;
	public int address;
	public int size;
}

public class r2w {
	public r2pipe.IR2Pipe Instance;
	public r2w() {
		Instance = new r2pipe.RlangPipe();
	}
	public r2w(string file) {
		Instance = new r2pipe.R2Pipe(file);
	}
	public string cmd(string cmd) {
		return Instance.RunCommand(cmd).Trim();
	}
	public dynamic cmdj(string cmd) {
		return JsonConvert.DeserializeObject(this.cmd(cmd));
	}
	public Opcode[] Opcodes(int n) {
		var ops = new List<Opcode>();
		foreach (var op in cmdj(""aoj 10"")) {
			ops.Add (op.ToObject<Opcode>());
		}
		return ops.ToArray();
	}
	public void Seek(string addr) {
		cmd(""s "" + addr);
	}
}
			");
		args = ParseArgs(args);
		if (args == null) {
			/* exit */
			return;
		}
		if (args.Length > 0) {
			e.Run("var r2 = new r2w(\""+args[0]+"\");");
		} else {
			try {
				e.Run("var r2 = new r2w();");
			} catch (Exception _) {
				Console.WriteLine(@"
Cannot find R2PIPE environment. See: csharp-r2 -h
Run this from r2 like this: '#!pipe mono main.exe'
");
				return;
			}
		}
		if (RunArgs()) {
			this.shell = new CSharpShell (e);
		}
	}

	public void Run() {
		string[] nullArgs = new string[0];
		if (this.shell != null) {
			shell.Run (nullArgs);
		}
	}
}
