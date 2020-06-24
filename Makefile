
all : client server
client : client.o cryptoSys.o clientChild.o
	g++ -o client client.o cryptoSys.o clientChild.o -lcrypto -lssl -lpthread
client.o : client.cc
	g++ -c -o client.o client.cc
cryptoSys.o : cryptoSys.cc
	g++ -c -o cryptoSys.o cryptoSys.cc
clientChild.o : clientChild.cc
	g++ -c -o clientChild.o clientChild.cc
server : server.o chatRoom.o
	g++ -o server server.o chatRoom.o -lpthread
server.o : server.cc
	g++ -c -o server.o server.cc
chatRoom.o : chatRoom.cc
	g++ -c -o chatRoom.o chatRoom.cc
clean:
	rm *.o client server
