FILE=jna-4.0.0.jar
URL=http://repo1.maven.org/maven2/net/java/dev/jna/jna/4.0.0

all: jna.jar
	javac -cp jna.jar:. AsmExample.java RAsmCode.java RAsm.java
	java -cp jna.jar:. AsmExample

all2: jna.jar
	javac -cp jna.jar:. HelloJNA.java
	java -cp jna.jar:. HelloJNA

jna.jar:
	wget -c $(URL)/$(FILE)
	ln -fs $(FILE) jna.jar

clean:
	rm -f *.class
