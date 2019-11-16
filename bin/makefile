all: def run info html

def:
	g++ -Wall -g -c -o pkinfo_shared.o pkinfo_shared.c
	g++ -Wall -g -c -o pcap.o pcap.c
	g++ -Wall -g -c -o filter.o filter.c
	g++ -Wall -g -c -o demo.o demo.c
	g++ -Wall -o demo demo.o filter.o pcap.o pkinfo_shared.o
	g++ -o gtest_pcap gtest_pcap.c pcap.c filter.c pkinfo_shared.c -lgtest -lpthread -g -Wall -Wshadow -fprofile-arcs -ftest-coverage
	
run:
	./gtest_pcap

info:
	gcov gtest_pcap.c && gcov pcap.c && gcov filter.c

html:
	lcov -c -d . -o pcap_gcov.info && genhtml -o pcap_html pcap_gcov.info

check:
	valgrind --leak-check=full -v ./demo

.PHONY: clean

clean: 
	rm -f *.o *.gcda *.gcno *.gcov pcap_gcov.info
	rm -f demo
	rm -f gtest_pcap
	rm -rf pcap_html

