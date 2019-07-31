COMPILER = gcc
CFLAGS = -Wall -pedantic -g

LIBS = -lcrypto

EXES = parallel_search_keyspace generate_ciphertext decrypt_ciphertext search_keyspace

all: ${EXES}

parallel_search_keyspace: parallel_search_keyspace.c
	${COMPILER} ${CFLAGS} parallel_search_keyspace.c ${LIBS} -o parallel_search_keyspace

generate_ciphertext: generate_ciphertext.c
	${COMPILER} ${CFLAGS} generate_ciphertext.c ${LIBS} -o generate_ciphertext

decrypt_ciphertext: decrypt_ciphertext.c
	${COMPILER} ${CFLAGS} decrypt_ciphertext.c ${LIBS} -o decrypt_ciphertext

search_keyspace: search_keyspace.c
	${COMPILER} ${CFLAGS} search_keyspace.c ${LIBS} -o search_keyspace

clean:
	rm -f *.o *~