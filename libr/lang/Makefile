all: py v
#csharp

v vlang:
	$(MAKE) -C p vlang
	$(MAKE) -C p vlang-install

py python:
	$(MAKE) -C p python
	$(MAKE) -C p python-install

csharp:
	$(MAKE) -C p csharp
	$(MAKE) -C repl-cs

csharp-install:
	$(MAKE) -C p csharp-install
	$(MAKE) -C repl-cs install

csharp-uninstall:
	$(MAKE) -C p csharp-uninstall
	$(MAKE) -C repl-cs uninstall
