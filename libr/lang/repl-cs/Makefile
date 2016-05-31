R2PIPE=../../../r2pipe/dotnet/r2pipe/R2Pipe.cs
R2PIPE+=../../../r2pipe/dotnet/r2pipe/IR2Pipe.cs
R2PIPE+=../../../r2pipe/dotnet/r2pipe/RlangPipe.cs
R2PIPE+=../../../r2pipe/dotnet/r2pipe/CmdQueue.cs
R2PIPE+=../../../r2pipe/dotnet/r2pipe/HttpR2Pipe.cs
R2PIPE+=../../../r2pipe/dotnet/r2pipe/QueuedR2Pipe.cs

BIN=main.exe
SCR=csharp-r2

all: NewtonSoft.Json.dll r2pipe.dll
	mcs -out:$(BIN) main.cs shell.cs getline.cs \
		-r:Mono.CSharp -r:System.Net.Http \
		-r:Mono.Posix -r:r2pipe -r:NewtonSoft.Json
	echo '#!/bin/sh' > $(SCR)
	echo 'mono $(shell pwd)/main.exe $$@' >> $(SCR)
	chmod +x $(SCR)

NewtonSoft.Json.dll:
	gunzip -k NewtonSoft.Json.dll.gz

r2pipe.dll:
	gunzip -k r2pipe.dll.gz

install:
	cp -f $(SCR) ~/.config/radare2/bin

uninstall:
	rm -f ~/.config/radare2/bin/$(SCR)

clean:
	rm -f $(BIN)
	rm -f r2repl
