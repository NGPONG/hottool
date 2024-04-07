all : hotfix hotfind

.PHONY : all

hotfix: crossprocess.o find_sym_addr.o hook.o hotfix.o
	g++ hotfix.o crossprocess.o find_sym_addr.o hook.o -funsigned-char -Wl,-export-dynamic -g -O0 -o hotfix

hotfind: crossprocess.o find_sym_addr.o hook.o hotfind.o
	g++ hotfind.o crossprocess.o find_sym_addr.o hook.o -funsigned-char -Wl,-export-dynamic -g -O0 -o hotfind

crossprocess.o: crossprocess.cpp crossprocess.h
	g++ -c crossprocess.cpp -g -O0 -funsigned-char -Wl,-export-dynamic

hook.o: hook.cpp hook.h
	g++ -c hook.cpp -g -O0 -funsigned-char -Wl,-export-dynamic

find_sym_addr.o: find_sym_addr.cpp find_sym_addr.h
	g++ -c find_sym_addr.cpp -g -O0 -funsigned-char -Wl,-export-dynamic

hotfix.o: hotfix.cpp
	g++ -c hotfix.cpp -g -O0 -funsigned-char -Wl,-export-dynamic

hotfind.o: hotfind.cpp
	g++ -c hotfind.cpp -g -O0 -funsigned-char -Wl,-export-dynamic

clean:
	rm -f *.o hotfix hotfind
