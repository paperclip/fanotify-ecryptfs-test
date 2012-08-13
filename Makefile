
all : FanotifyMultiThreadScanner FanotifySingleEventScanner

FanotifyMultiThreadScanner : MultiThreadScanner.cpp
	g++ -pthread $< -o $@


FanotifySingleEventScanner : SingleEventScanner.cpp
	g++ -pthread $< -o $@

