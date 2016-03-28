#Makefile for NIS Project
JAVAC = javac
JFLAGS = -g

.SUFFIXES: .java .class

.java.class:
	$(JAVAC) $(JFLAGS) $*.java

CLASSES = MultiThreadChatServerSync.java MultiThreadChatClient.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
runServer:
	java MultiThreadChatServerSync
runChat:
	java MultiThreadChatClient
