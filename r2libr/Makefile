all: radare2
	python setup.py build

clean:
	rm -rf build

mrproper: clean
	rm -rf dist

install:
	python setup.py install

uninstall:
	pip3 uninstall -y r2libr

radare2:
	git clone --depth=1 https://github.com/radareorg/radare2
