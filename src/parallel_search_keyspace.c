#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAX_KEY_LENGTH 32
#define MAX_BUFFER 4096
#define TRUE 1
#define FALSE 0

/*
Parallel Search Keyspace
------------------------
Author: Matthew Gray
Student No.: 220186070
Email: mgray44@myune.edu.au

This program parallelises a search through a
keyspace for a missing number of bytes in an
encryption/decryption key.

To compile this program, use the command:

make parallel_search_keyspace

To the run the program, use the command 
parallel_search_keyspace + the number of processes/nodes
to use (limited to 25) + the partial key e.g.:

parallel_search_keyspace 20 4+zxQ8dwmYVcH+dznll3BpSR3DyX
*/

int nodeid;

/*
Function: parse_args
----------------------
Checks the arguments passed the program from the command line
and performs some basic checks and calculations.

Parameters
-----------
argc: argument count from main
argv: argument array
nproc: number of processes to create
kd: key data
kd_len: length of key data
u_len: unknown/missing element of key

Return
---------
Negative int on failure

 */
int parse_args(int argc, char **argv, int *nproc, unsigned char *kd, int *kd_len, int *u_len) {
  if ( (argc != 3) || ((*nproc = atoi (argv[1])) <= 0)) {
    fprintf (stderr, "Usage: %s nprocs keydata\n", argv[0]);
    return(-1); 
  }
  // Limit number of processes the user can create
  if ((*nproc = atoi(argv[1])) > 25) {
    fprintf(stderr, "Limit processes to between 1 and 25");
    return(-1);
  }
  *kd_len = strlen(argv[2]);
  // Calculate missing bytes from string
  *u_len = MAX_KEY_LENGTH - *kd_len;

  // Only use 32 most significant bytes
  if(*kd_len > MAX_KEY_LENGTH) *kd_len = MAX_KEY_LENGTH;

  // Copy in keydata and pad the missing bytes with 0s
  for (int i = 0; i < *kd_len; i++) {
    kd[i] = argv[2][i];
  }
  for (int i = *kd_len; i < MAX_KEY_LENGTH; i++) {
    kd[i] = 0;
  }
  return(0);
}

/*
Function: read_file
--------------------
Opens file and reads contents into buffer

Parameters
-----------
fname: filename
buf: buffer for file contents
len: length of contents

Return
-------
Negative int on failure
 */
int read_file(char *fname, unsigned char *buf, int len)
{
  // Open file
  FILE *file = fopen(fname, "r");

  // Error check
  if (file == NULL) {
    perror("File could not be opened.");
    fprintf(stderr, "Could not open file: %s\n", fname);
    exit(-1);
  }

  // Read file contents into buffer
  int read = fread(buf, len, 1, file);
  // Double check errors
  if (read < 0) {
    perror("File was empty");
    exit(-2);
  }
  fclose(file);

  return(read);
}

/*
Function: make_trivial_ring
-----------------------------
Creates a trivial ring to which we
add our nodes/processes to

Returns
---------
Negative int on failure 
 */
int make_trivial_ring()
{
  int fd[2];
  if (pipe(fd) == -1) {
    return(-1);
  }
  if((dup2(fd[0], STDIN_FILENO) == -1) ||
      (dup2(fd[1], STDOUT_FILENO) == -1))
    return(-2);
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1))   
    return(-3); 
  return(0);
}

/*
Function: add_node
-------------------
Adds a process to the ring

Parameters
-----------
pid: process id

Return
----------
Negative int on failure
 */
int add_node(int *pid)
{
  int fd[2];
  if (pipe(fd) == -1) 
    return(-1); 
  if ((*pid = fork()) == -1)
    return(-2); 
  if(*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0)
    return(-3); 
  if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0)
    return(-4); 
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1)) 
    return(-5);
  return(0);
}

/*
Function: make_ring
---------------------
Creates a ring of processes and joins them together

Parameters
-----------
n: number of processes in the ring

Return
--------
counter i
 */
int make_ring(int n)
{
  if(make_trivial_ring() < 0) {
    perror("Could not create make trivial ring");
    exit(EXIT_FAILURE);
  }

  int c_pid, i;
  for (i = 1; i <= n; i++) {
    if (add_node(&c_pid) < 0) {
      perror("Could not add new node to ring");
      exit(EXIT_FAILURE);
    }
    if (c_pid) break;
  }
  return i;
}

/*
Function: copy_key
-------------------
Copies a key into a buffer

Parameters
-----------
key: key to be copied
buf: buffer to copy key into
len: length of key
 */
void copy_key(unsigned char* key, unsigned char* buf, int len)
{
  for (int i = 0; i < len;i++) {
    buf[i] = key[i];
  }
}

/*
Function: aes_init
--------------------
Initialises aes decryption context

Parameters
--------------
keyin: key to be used in decryption
d_ctx: decryption context

Returns
---------
0 on success
 */
int aes_init(unsigned char* keyin, EVP_CIPHER_CTX* d_ctx)
{
    int ec = EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, keyin, keyin);
    if (ec < 1) {
      perror("Failed to initialize EVP decryption");
      kill(0, SIGTERM);
    }
    return 0;
}

/*
Function: aes_decrypt
-----------------------
Decrypts a length of cipher text 

Parameters
---------------
de: decryption cipher context
c_in: cipher input
c_len: length of cipher

Return
--------
decrypted plain text
*/
unsigned char *aes_decrypt(EVP_CIPHER_CTX* de, unsigned char* c_in, int* c_len)
{
    // Allocate lengths of decripted text
    int p_len = *c_len;
    int f_len = 0;

    unsigned char* p_txt = malloc(p_len);

    EVP_DecryptUpdate(de, p_txt, &p_len, c_in, *c_len);
    EVP_DecryptFinal_ex(de, p_txt + p_len, &f_len);

    return p_txt;
}

/*
Function: signal_handler
-------------------------
Handles the signal sent after a node has finished searcing
the keyspace or has found the key

Parameters
-----------
signum: Predefined number that is assigned to this handling function */
void signal_handler(int signum)
{
  unsigned char key[MAX_KEY_LENGTH];

  if (nodeid == 1) {
    // Parent node writes empty key to indicate failure then waits
    // for input from ring
    write(STDOUT_FILENO, key, MAX_KEY_LENGTH);
    read(STDIN_FILENO, key, MAX_KEY_LENGTH);

    // Reopen stdout and redirect output
    freopen("/dev/tty", "a", stdout);

    // Check to see if the parent received no key/empty buffer
    int found = FALSE;
    for (int i = 0; i < MAX_KEY_LENGTH; i++) {
      found |= key[i] != '\0';
    }
    if (found == FALSE) {
      fprintf(stderr, "Unable to find key\n");
      exit(-1);
    }
    // Print out the full decryption key
    printf("\nKey: ");
    for (int i = 0; i < MAX_KEY_LENGTH; i++) {
      printf("%c", key[i]);
    }
    printf("\n");

    exit(0);
  } else {
    // Child nodes pass key through the ring and then quit
    read(STDIN_FILENO, key, MAX_KEY_LENGTH);
    write(STDOUT_FILENO, key, MAX_KEY_LENGTH);
    exit(0);
  }

}
/*
Function: update_key
---------------------
Updates the missing bytes of the trial key with the next guess

Paramaters
------------
t_key: trial key to be used in decryption attempt
k_low: Lowest bits of the key
c: counter keeping track of number of attempts
u_len: unknown elements of key
 */

void update_key(unsigned char* t_key, unsigned long k_low, int c, int u_len)
{
  // Get each new key by performing an or operation on the lowbits of the key and the counter
  unsigned long trialLowBits = k_low | c;
  // Overwrite the missing bytes
  for(int i = u_len; i > 0; i--) {
    t_key[MAX_KEY_LENGTH - i] = (unsigned char)(trialLowBits >> ((i-1)*8));
  }
}

int main(int argc, char **argv)
{
  // Set up signal handler for process termination
  if (signal(SIGTERM, signal_handler) == SIG_ERR) {
    perror("Signal handler not assigned");
    return(-1);
  }

  // Parse arguments: Number of proccesses, length of key data, missing bytes
  int nproc, kdlen, i, y, u_len;
  unsigned char keydata[MAX_KEY_LENGTH];
  unsigned char key[MAX_KEY_LENGTH];

  // Parse arguments
  if (parse_args(argc, argv, &nproc, keydata, &kdlen, &u_len)) exit(-1);

  // Read files into memory
  unsigned char c_in[MAX_BUFFER];
  char p_in[MAX_BUFFER];

  // Read in plain cipher text
  read_file("cipher.txt", (unsigned char *)&c_in, 32);
  int c_len = strlen((const char*)c_in);
  read_file("plain.txt", (unsigned char *)&p_in, 28);
  int p_len = strlen(p_in);

  // Print out plain and cipher text
  printf("\nPlain:");
  for(y=0;y<p_len;y++){
    printf("%c",p_in[y]);  
  }
  printf("\n");
  printf("\nCipher:");
  for(y=0;y<c_len;y++){
    printf("%c",c_in[y]);  
  }
  printf("\n");

  // Copy over keydata into new buffer
  copy_key(keydata, key, MAX_KEY_LENGTH);

  // Get the lowest bits of the key corresponding to the missing/unknown elements
  unsigned long keyLowBits = 0;
  for (i = u_len; i > 0; i--) {
    keyLowBits |= ((unsigned long)(
        key[MAX_KEY_LENGTH - i] & 0xFFFF) << (i-1) * 8
      );
  }

  // Find ceiling of missing keyspace
  unsigned long maxSpace = 0;
  maxSpace = ((unsigned long)1 << ((u_len)*8)) - 1;
  // Calculate the size of each processes keyspace
  unsigned long space_size = maxSpace/nproc;
  // Find any values cut off by division
  int m = maxSpace % nproc;

  // Initialise ring topology
  nodeid = make_ring(nproc);

  // Calculate each processes keyspace
  unsigned long keyspace = space_size*(nodeid - 1);
  // Add missing value onto final nodes keyspace
  if (nodeid == (nproc + 1)) keyspace += m;

  unsigned char trialkey[MAX_KEY_LENGTH];
  copy_key(key, trialkey, MAX_KEY_LENGTH);

  int found = FALSE;

  // Set up decryption context
  EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(de);

  unsigned long floor = space_size*(nodeid -  2);
  
  // For all processes except the parent
  if (nodeid > 1) {
    // Iterate through the keyspace
    for(unsigned long c = floor; c <= keyspace; c++) {
      update_key(trialkey, keyLowBits, c, u_len);
      aes_init(trialkey, de);

      char *p_out = (char *)aes_decrypt(de, c_in, &c_len);

      if (strncmp(p_out, p_in, p_len) == 0) {
        write(STDOUT_FILENO, trialkey, MAX_KEY_LENGTH);
        found = TRUE;
        break;
      }
      free(p_out);
    }
  }

  EVP_CIPHER_CTX_cleanup(de);
  EVP_cleanup();

  // Shutdown processes
  if (found == TRUE) {
    kill(0, SIGTERM);
  } else {
    kill(getpid(), SIGTERM);
  }
  return(0);
}