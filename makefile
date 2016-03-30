#Makefile for NIS Project
JAVAC = javac
JFLAGS = -g

.SUFFIXES: .java .class

.java.class:
	$(JAVAC) $(JFLAGS) $*.java

CLASSES = Server.java Client.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
runServer:
	java Server
runClient:
	java Client
