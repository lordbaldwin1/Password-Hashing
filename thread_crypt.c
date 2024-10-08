#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <crypt.h>
#include "thread_crypt.h"

#define MAX_THREADS 20
#define MAX_SALT_LEN 32
#define MAX_PASSWORD_LEN 256
#define MAX_HASH_LEN 256


void generate_salt(char *salt, int algorithm, int salt_length, long num_rounds);
void *hash_function(void *arg);
void read_passwords(char ***passwords, int *num_passwords, const char *filename);



//const char *SALT_CHARS = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
pthread_mutex_t output_mutex;

typedef struct {
    int thread_id;
    int total_threads;
    char **passwords;
    int num_passwords;
    char **output;
} thread_data_t;

typedef struct {
    char *input_filename;
    char *output_filename;
    int algorithm;
    int salt_length;
    long num_rounds;
    int num_threads;
    int verbose;
} global_args_t;

global_args_t global_args = {
    .num_threads = 1, // Default to 1 thread
    .salt_length = 2, // Default salt length for DES
    .num_rounds = 5000 // Default rounds for SHA algorithms
};

void generate_salt(char *salt, int algorithm, int salt_length, long num_rounds) {
    char prefix[30] = "";
    int prefix_len;
    if (algorithm == 5 || algorithm == 6) {
        snprintf(prefix, sizeof(prefix), "$%d$rounds=%ld$", algorithm, num_rounds);
    } else if (algorithm == 1) {
        strcpy(prefix, "$1$");
    }

    strcpy(salt, prefix);
    prefix_len = strlen(prefix);
    for (int i = 0; i < salt_length; ++i) {
        salt[prefix_len + i] = SALT_CHARS[rand() % (sizeof(SALT_CHARS) - 1)];
    }
    salt[prefix_len + salt_length] = '\0';
}

void *hash_function(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;

    char salt[MAX_SALT_LEN];
    struct crypt_data cdata;
    if(global_args.salt_length < 4 && global_args.algorithm == 1)
	    global_args.salt_length = 4;
    if(global_args.salt_length < 8 && (global_args.algorithm == 5 || global_args.algorithm == 6))
	    global_args.salt_length = 8;
    cdata.initialized = 0;

    for (int i = data->thread_id; i < data->num_passwords; i += data->total_threads) {
	char *hash;
        generate_salt(salt, global_args.algorithm, global_args.salt_length, global_args.num_rounds);
        hash = crypt_r(data->passwords[i], salt, &cdata);
        
        pthread_mutex_lock(&output_mutex);
        snprintf(data->output[i], MAX_PASSWORD_LEN + MAX_HASH_LEN, "%s:%s", data->passwords[i], hash);
        pthread_mutex_unlock(&output_mutex);
    }

    return NULL;
}

void read_passwords(char ***passwords, int *num_passwords, const char *filename) {
	char line[MAX_PASSWORD_LEN];
	char **local_passwords = NULL;
	int count = 0;
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    //char line[MAX_PASSWORD_LEN];
    //char **local_passwords = NULL;
    //int count = 0;

    while (fgets(line, MAX_PASSWORD_LEN, file)) {
        line[strcspn(line, "\n")] = 0;
        local_passwords = realloc(local_passwords, sizeof(char*) * (count + 1));
        local_passwords[count] = strdup(line);
        count++;
    }

    fclose(file);
    *passwords = local_passwords;
    *num_passwords = count;
}

int main(int argc, char *argv[]) {
    int opt;
    char **passwords = NULL;
    int num_passwords = 0;
    char **output;
    FILE *out_file;
    pthread_t threads[MAX_THREADS];
    thread_data_t thread_data[MAX_THREADS];
    pthread_mutex_init(&output_mutex, NULL);
    while ((opt = getopt(argc, argv, "i:o:a:l:R:t:r:vh")) != -1) {
        switch (opt) {
            case 'i':
                global_args.input_filename = optarg;
                break;
            case 'o':
                global_args.output_filename = optarg;
                break;
            case 'a':
                global_args.algorithm = atoi(optarg);
                // Set default salt lengths based on the algorithm
                if (global_args.algorithm == 1) {
                    global_args.salt_length = 8;
                } else if (global_args.algorithm == 5 || global_args.algorithm == 6) {
                    global_args.salt_length = 16;
                }
                break;
            case 'l':
                global_args.salt_length = atoi(optarg);
                break;
            case 'R':
                srand(atoi(optarg)); // Set random seed
                break;
            case 't':
                global_args.num_threads = atoi(optarg);
                if (global_args.num_threads <= 0 || global_args.num_threads > MAX_THREADS) {
                    fprintf(stderr, "Invalid number of threads. Must be between 1 and %d.\n", MAX_THREADS);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'r':
                global_args.num_rounds = atol(optarg);
                break;
            case 'v':
                global_args.verbose = 1;
		printf("verbose enabled\n");
                break;
            case 'h':
                printf("./thread_crypt ...\n");
		printf("	Options: i:o:hva:l:R:t:r:\n");
		printf("	-i file		input file name (required)\n");
		printf("	-o file		output file name (default stdout)\n");
		printf("	-a #		algorithm to use for hashing [0,1,5,6] (default 0 = DES)\n");
		printf("	-l #		length of salt (default 2 for DES, 8 for MD-5, 16 for SHA)\n");
		printf("	-r #		rounds to use for SHA-256, or SHA-512 (default 5000)\n");
		printf("	-R #		seed for rand() (default none)\n");
		printf("	-t #		number of threads to create (default 1)\n");
		printf("	-v		enable verbose mode\n");
		printf("	-h		helpful text\n");
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "Usage: %s -i inputfile -o outputfile -a algorithm -l saltlength -R seed -t threads -r rounds -v (verbose)\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!global_args.input_filename) {
        fprintf(stderr, "Input file is required.\n");
        exit(EXIT_FAILURE);
    }

    // Read passwords from the file
    passwords = NULL;
    num_passwords = 0;
    read_passwords(&passwords, &num_passwords, global_args.input_filename);

    // Allocate memory for thread output
    output = malloc(num_passwords * sizeof(char *));
    for (int i = 0; i < num_passwords; i++) {
        output[i] = malloc(MAX_PASSWORD_LEN + MAX_HASH_LEN);
    }

    // Create threads
    //pthread_t threads[MAX_THREADS];
    //thread_data_t thread_data[MAX_THREADS];
    //pthread_mutex_init(&output_mutex, NULL);

    for (int i = 0; i < global_args.num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].total_threads = global_args.num_threads;
        thread_data[i].passwords = passwords;
        thread_data[i].num_passwords = num_passwords;
        thread_data[i].output = output;
        pthread_create(&threads[i], NULL, hash_function, (void *)&thread_data[i]);
    }

    // Join threads
    for (int i = 0; i < global_args.num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Write output
    out_file = global_args.output_filename ? fopen(global_args.output_filename, "w") : stdout;
    if (out_file) {
        for (int i = 0; i < num_passwords; i++) {
            fprintf(out_file, "%s\n", output[i]);
        }
        if (global_args.output_filename) {
            fclose(out_file);
        }
    } else {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    // Cleanup
    pthread_mutex_destroy(&output_mutex);
    for (int i = 0; i < num_passwords; i++) {
        free(passwords[i]);
        free(output[i]);
    }
    free(passwords);
    free(output);

    return 0;
}
