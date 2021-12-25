FILE=jna-5.10.0.jar
URL=https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.10.0

all: jna bindings
	java -cp $(FILE):bindings.jar example.java

bindings:
	find org -iname '*.java' > sources.txt
	javac -sourcepath org -d build/ -cp $(FILE) --release 11 @sources.txt
	rm sources.txt
	cd build ; find org -iname '*.class' > classes.txt ; jar --create --file ../bindings.jar @classes.txt ; cd ..
	rm -rf build/
	
jna:
	wget -c $(URL)/$(FILE)

clean:
	rm $(FILE)
	rm bindings.jar
