all:
	g++ server.cpp -o server \
		-std=c++17 \
		-I/scratch/mdb326/openfhe-development/src \
		-I/scratch/mdb326/openfhe-development/src/core/include \
		-I/scratch/mdb326/openfhe-development/src/pke/include \
		-I/scratch/mdb326/openfhe-development/src/binfhe/include \
		-I/scratch/mdb326/openfhe-development/build/src/core \
		-I/scratch/mdb326/openfhe-development/third-party/cereal/include \
		-I/scratch/mdb326/openfhe-development/third-party/binfhe/include \
		-L/scratch/mdb326/openfhe-development/build/lib \
		-Wl,-rpath,/scratch/mdb326/openfhe-development/build/lib \
		-lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe

	g++ client.cpp -o client \
		-std=c++17 \
		-I/scratch/mdb326/openfhe-development/src \
		-I/scratch/mdb326/openfhe-development/src/core/include \
		-I/scratch/mdb326/openfhe-development/src/pke/include \
		-I/scratch/mdb326/openfhe-development/src/binfhe/include \
		-I/scratch/mdb326/openfhe-development/build/src/core \
		-I/scratch/mdb326/openfhe-development/third-party/cereal/include \
		-I/scratch/mdb326/openfhe-development/third-party/binfhe/include \
		-L/scratch/mdb326/openfhe-development/build/lib \
		-Wl,-rpath,/scratch/mdb326/openfhe-development/build/lib \
		-lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe

unencrypted:
	g++ clientUnencrypted.cpp -o clientUnencrypted
	g++ serverUnencrypted.cpp -o serverUnencrypted

multi:
	g++ multiclient.cpp -o multiclient \
		-std=c++17 \
		-I/scratch/mdb326/openfhe-development/src \
		-I/scratch/mdb326/openfhe-development/src/core/include \
		-I/scratch/mdb326/openfhe-development/src/pke/include \
		-I/scratch/mdb326/openfhe-development/src/binfhe/include \
		-I/scratch/mdb326/openfhe-development/build/src/core \
		-I/scratch/mdb326/openfhe-development/third-party/cereal/include \
		-I/scratch/mdb326/openfhe-development/third-party/binfhe/include \
		-L/scratch/mdb326/openfhe-development/build/lib \
		-Wl,-rpath,/scratch/mdb326/openfhe-development/build/lib \
		-lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe

	g++ multiserver.cpp -o multiserver \
		-std=c++17 \
		-I/scratch/mdb326/openfhe-development/src \
		-I/scratch/mdb326/openfhe-development/src/core/include \
		-I/scratch/mdb326/openfhe-development/src/pke/include \
		-I/scratch/mdb326/openfhe-development/src/binfhe/include \
		-I/scratch/mdb326/openfhe-development/build/src/core \
		-I/scratch/mdb326/openfhe-development/third-party/cereal/include \
		-I/scratch/mdb326/openfhe-development/third-party/binfhe/include \
		-L/scratch/mdb326/openfhe-development/build/lib \
		-Wl,-rpath,/scratch/mdb326/openfhe-development/build/lib \
		-lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -lpthread

multiun:
	g++ multiclientun.cpp -o clientun
	g++ multiserverun.cpp -o multiun -pthread

bfv:
	g++ bfv.cpp -o bfv -O3

clean:
	rm client
	rm server
	rm clientUnencrypted
	rm serverUnencrypted
	rm multiclient
	rm multiserver
	rm clientun
	rm multiun
