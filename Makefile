all:	permission watcher_thread scripting
	g++ -Wall obj/permission.o obj/watcher_thread.o obj/scripting.o -o bin/dir1984 src/main.cpp  -lpthread

permission:	src/permission.h src/permission.cpp
	g++ -Wall -c src/permission.cpp -o obj/permission.o

watcher_thread:	src/watcher_thread.h src/watcher_thread.cpp
	g++ -Wall -c src/watcher_thread.cpp -o obj/watcher_thread.o 

scripting:	src/scripting.h src/scripting.cpp
	g++ -Wall -c src/scripting.cpp -o obj/scripting.o

clean:
	rm obj/permission.o obj/watcher_thread.o bin/dir1984
install:
	mkdir -p /etc/dir1984
	cp bin/dir1984 /bin
	cp sh/getdirs.sh /etc/dir1984/getdirs.sh
	cp conf/dir1984.conf /etc/dir1984/dir1984.conf
	cp sh/dirservice /etc/init.d/dir1984
	chmod +x /etc/init.d/dir1984
	chmod +x /etc/dir1984/getdirs.sh
	update-rc.d dir1984 defaults
