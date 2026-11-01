/**
 * SecFES - Secure File Encryption Software
 * @date 2023-5-9
 * @update 2026-10-31
 *
 * Original undergraduate version (2023). See README.md for a security review
 * of known weaknesses in this design.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <time.h>

#define MAX_THREADS 10 // Maximum number of threads
#define MAX_FILES 20   // Maximum number of files

#define ANSI_RED     "\x1b[31m" // Red color code for console output
#define ANSI_GREEN   "\x1b[32m" // Green color code for console output
#define ANSI_BLUE    "\x1b[34m" // Blue color code for console output
#define ANSI_YELLOW  "\x1b[33m" // Yellow color code for console output
#define ANSI_MAGENTA "\x1b[35m" // Magenta color code for console output
#define ANSI_RESET   "\x1b[0m"  // Reset color code for console output

char* filenames[MAX_FILES]; // Array of file names
bool is_encrypt[MAX_FILES]; // Array indicating whether each file should be encrypted or decrypted
int n_files = 0;            // Number of files

unsigned char aes_key[257]; // AES encryption key

pthread_t thread_pool[MAX_THREADS];                     // Array of thread identifiers (thread pool)
pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for the task queue
pthread_cond_t task_cond = PTHREAD_COND_INITIALIZER;    // Condition variable for the task queue

int n_threads = 0;         // Current number of threads
int current_task = 0;      // Current task number
int n_tasks_completed = 0; // Number of completed tasks

// Structure representing a task, including the file name, encryption/decryption operation, and thread number
typedef struct {
    char* filename;
    bool is_encrypt;
    int thread_no;
} Task;

// Encryption/decryption function using AES-256 algorithm
void encrypt_decrypt_file(char* filename, bool is_encrypt, unsigned char* aes_key) {
    FILE* fp = fopen(filename, "rb+"); // Open the file for reading and writing in binary mode
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file %s: %s\n", filename, strerror(errno)); // Print an error message if the file failed to open
        return;
    }

    // Get the file size
    fseek(fp, 0, SEEK_END); // Move the file pointer to the end of the file
    long size = ftell(fp);  // Get the current position of the file pointer, which represents the file size
    fseek(fp, 0, SEEK_SET); // Move the file pointer back to the beginning of the file

    // Allocate memory to store the file data
    unsigned char* in_data = (unsigned char*)malloc(size); // Create a buffer of size 'size' to store the file data
    fread(in_data, sizeof(char), size, fp);                // Read the file data into the buffer
    fclose(fp);                                            // Close the file

    // AES-256 encryption/decryption initialization vector
    unsigned char aes_iv[] = "0123456789012345";

    // Allocate memory to store the encryption/decryption result
    unsigned char* out_data = (unsigned char*)malloc(size + AES_BLOCK_SIZE); // Create a buffer to store the encrypted/decrypted data

    // Create an EVP_CIPHER_CTX context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Initialize the AES encryption algorithm in CBC mode
    if (is_encrypt) {
        EVP_EncryptInit(ctx, EVP_aes_256_cbc(), aes_key, aes_iv);
    } else {
        EVP_DecryptInit(ctx, EVP_aes_256_cbc(), aes_key, aes_iv);
    }

    int outlen;
    if (is_encrypt) {
        // Encrypt the data
        EVP_EncryptUpdate(ctx, out_data, &outlen, in_data, size);
    } else {
        // Decrypt the data
        EVP_DecryptUpdate(ctx, out_data, &outlen, in_data, size);
    }

    int final_outlen;
    if (is_encrypt) {
        EVP_EncryptFinal(ctx, out_data + outlen, &final_outlen);
    } else {
        EVP_DecryptFinal(ctx, out_data + outlen, &final_outlen);
    }

    // Save the encryption/decryption result back to the file
    fp = fopen(filename, "wb"); // Open the file for writing in binary mode
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file %s: %s\n", filename, strerror(errno)); // Print an error message if the file failed to open
        return;
    }

    fwrite(out_data, sizeof(char), outlen + final_outlen, fp); // Write the encrypted/decrypted data to the file
    fclose(fp);                                                // Close the file

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    // Free memory
    free(in_data);
    free(out_data);
}

// Thread function that retrieves tasks from the task queue and executes them
void* worker(void* arg) {
    int thread_no = *(int*)arg; // Get the thread number from the argument
    free(arg);                  // Free the memory allocated for the argument

    while (true) {
        // Retrieve a task
        pthread_mutex_lock(&task_mutex); // Acquire the task mutex

        while (current_task >= n_files) {
            if (n_tasks_completed >= n_files) {
                // All tasks have been processed, thread exits
                pthread_mutex_unlock(&task_mutex);
                pthread_cond_signal(&task_cond); // Wake up other threads
                break;
            } else {
                // Wait for other threads to complete tasks
                printf(ANSI_YELLOW "Thread %d: Waiting for tasks.\n" ANSI_RESET, thread_no); // Print a message indicating thread is waiting for tasks
                pthread_cond_wait(&task_cond, &task_mutex); // Wait for the condition variable to be signaled
            }
        }

        if (current_task >= n_files) {
            // All tasks have been processed, thread exits
            printf(ANSI_MAGENTA "Thread %d: No more tasks. Exiting.\n" ANSI_RESET, thread_no); // Print a message indicating thread is exiting
            pthread_mutex_unlock(&task_mutex);
            pthread_exit(NULL); // Thread exits
        }

        int task_no = current_task++;      // Get a task number
        pthread_mutex_unlock(&task_mutex); // Release the task mutex

        // Execute the task
        char* filename = filenames[task_no];         // Get the filename from the task
        bool task_is_encrypt = is_encrypt[task_no];  // Get the encryption/decryption flag from the task
        if (task_is_encrypt) {
            printf("Thread %d: Encrypting File %s.\n", thread_no, filename); // Print a message indicating the file is being encrypted
            encrypt_decrypt_file(filename, true, aes_key);                  // Call the encryption/decryption function with the appropriate parameters
            printf(ANSI_BLUE "Thread %d: Finished Encrypted %s\n" ANSI_RESET, thread_no, filename); // Print a message indicating the file has been encrypted
        } else {
            printf("Thread %d: Decrypting File %s.\n", thread_no, filename); // Print a message indicating the file is being decrypted
            encrypt_decrypt_file(filename, false, aes_key);                 // Call the encryption/decryption function with the appropriate parameters
            printf(ANSI_GREEN "Thread %d: Finished Decrypted %s\n" ANSI_RESET, thread_no, filename); // Print a message indicating the file has been decrypted
        }

        pthread_mutex_lock(&task_mutex);
        n_tasks_completed++;
        pthread_mutex_unlock(&task_mutex);
        pthread_cond_signal(&task_cond); // Wake up other threads
    }

    pthread_exit(NULL);
}

// Function to daemonize the process
void daemonize() {
    pid_t pid;

    // Create a child process and let the parent process exit
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Create a new session, and make the child process the session leader and group leader
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    // Close standard input, standard output, and standard error streams
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Change the working directory to the root directory
    chdir("/");

    // Redirect standard input, standard output, and standard error streams to /dev/null or other log files
    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
}

int main(int argc, char** argv) {
    printf(ANSI_RED   "  ____            _____ _____ ____  " ANSI_RESET "\n");
    printf(ANSI_RED   " / ___|  ___  ___|  ___| ____/ ___| " ANSI_RESET "\n");
    printf(ANSI_BLUE  " \\___ \\ / _ \\/ __| |_  |  _| \\___ \\ " ANSI_RESET "\n");
    printf(ANSI_BLUE  "  ___) |  __/ (__|  _| | |___ ___) |" ANSI_RESET "\n");
    printf(ANSI_GREEN " |____/ \\___|\\___|_|   |_____|____/ " ANSI_RESET "\n");

    // To open the daemon, you need to cancel the following comment
    // daemonize();

    if (argc < 2) {
        printf("A required parameter is missing, please check the documentation [hint: -help] \n");
        return 1;
    }

    if (strcmp(argv[1], "-help") == 0) {
        printf(ANSI_GREEN "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" ANSI_RESET "\n");
        printf(ANSI_BLUE " SecFES is the abbreviation of Secure File Encryption Software, which provides an AES encryption method " ANSI_RESET "\n");
        printf(ANSI_BLUE " and is Cipher-block chaining (CBC) mode, which encrypts the file content you want to protect in blocks " ANSI_RESET "\n");
        printf(ANSI_BLUE " provide multi-threaded (de|en)cryption, using thread pool management can encrypt/decrypt multiple files " ANSI_RESET "\n");
        printf(ANSI_GREEN "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" ANSI_RESET "\n");
        printf("Usage: %s -k [32-byte AES key] [-e|-d] file1 file2 ... fileN \n", argv[0]);
        printf("   Or: %s -K [The 32-byte AES Key File] [-e|-d] file1 file2 ... fileN \n", argv[0]);
        printf("   Or: %s -k [32-byte AES key] [-E|-D] [folder] \n", argv[0]);
        printf("   Or: %s -K [The 32-byte AES Key File] [-E|-D] [folder] \n", argv[0]);
        printf("Options:\n");
        printf("-k: AES key used for encryption/decryption (required)\n");
        printf("-K: Read AES key from specified file (required)\n");
        printf("-e: Encrypt the specified files.\n");
        printf("-d: Decrypt the specified files.\n");
        printf("-E: Encrypt the all files under the specified folder.\n");
        printf("-D: Decrypt the all files under the specified folder.\n");
        printf("-help: Show SecFES help message.\n");
        return 0;
    }

    if (argc < 5) {
        printf("A required parameter is missing, please check the documentation [hint: -help] \n");
        return 1;
    }

    // Parsing Command Line Parameters
    bool is_encrypt_mode;

    if (strcmp(argv[1], "-k") != 0 && strcmp(argv[1], "-K") != 0) {
        printf("Invalid option: %s\n", argv[1]);
        printf("Please use -help for usage guideline!\n");
        return 1;
    }

    if (strcmp(argv[1], "-k") == 0) {
        if (strlen(argv[2]) != 256) {
            printf("Invalid AES key: %s\n", argv[2]);
            printf("AES key must be 256 characters in length\n");
            return 1;
        }
        memcpy(aes_key, argv[2], 257);
    }

    if (strcmp(argv[1], "-K") == 0) {
        char* keyfile = argv[2];
        FILE* fp = fopen(keyfile, "r");
        if (fp == NULL) {
            printf("Failed to open file %s\n", keyfile);
            return 1;
        }

        // determine file size
        fseek(fp, 0L, SEEK_END);
        size_t file_size = ftell(fp);
        rewind(fp);

        if (file_size != 256) {
            printf("Invalid AES key in file: %s\n", keyfile);
            printf("AES key in file must be 256 bytes in length\n");
            fclose(fp);
            return 1;
        }

        // Read file contents to buffer
        char key_buffer[257];
        size_t bytes_read = fread(key_buffer, 1, file_size, fp);
        (void)bytes_read;
        fclose(fp);

        // Copy buffer to aes_key array
        memcpy(aes_key, key_buffer, 256);
    }

    if (strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "-E") == 0) {
        is_encrypt_mode = true;
    } else if (strcmp(argv[3], "-d") == 0 || strcmp(argv[3], "-D") == 0) {
        is_encrypt_mode = false;
    } else {
        printf(ANSI_RED "Invalid operation: %s\n" ANSI_RESET, argv[3]);
        printf("Please run the -help for use guideline!\n");
        return 1;
    }

    // Multiple file mode for encryption and decryption
    if (strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "-d") == 0) {
        for (int i = 4; i < argc; i++) {
            if (n_files >= MAX_FILES) {
                printf(ANSI_RED "Maximum number of files reached.\n" ANSI_RESET);
                break;
            }

            filenames[n_files] = argv[i];
            is_encrypt[n_files] = is_encrypt_mode;
            n_files++;
        }
    }

    // File/folder mode for encryption/decryption
    if (strcmp(argv[3], "-E") == 0 || strcmp(argv[3], "-D") == 0) {
        // Open the folder/directory
        DIR* dir;
        struct dirent* ent;
        dir = opendir(argv[4]);
        if (dir == NULL) {
            printf(ANSI_RED "Failed to open directory: %s\n" ANSI_RESET, argv[4]);
            return 1;
        }

        // Traverse the files in the folder
        while ((ent = readdir(dir)) != NULL) {
            // Ignore "." and ".." directories
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
                continue;
            }

            // Construct the full path of the file
            char filepath[PATH_MAX];
            snprintf(filepath, PATH_MAX, "%s/%s", argv[4], ent->d_name);

            // Check if the task queue is full
            if (n_files >= MAX_FILES) {
                printf(ANSI_RED "Maximum number of files reached.\n" ANSI_RESET);
                break;
            }

            // Add the file to the task queue
            filenames[n_files] = strdup(filepath);
            is_encrypt[n_files] = is_encrypt_mode;
            n_files++;
        }

        closedir(dir);
    }

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time); // Record the start time of the program

    // Start the thread pool
    for (int i = 0; i < MAX_THREADS; i++) {
        int* thread_no = (int*)malloc(sizeof(int));
        *thread_no = i;
        pthread_create(&thread_pool[i], NULL, worker, thread_no);
        n_threads++;
    }

    // Wait for all threads to finish executing
    for (int i = 0; i < n_threads; i++) {
        pthread_join(thread_pool[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time); // Record the end time
    double total_time = (end_time.tv_sec - start_time.tv_sec) * 1000.0;  // Convert seconds to milliseconds
    total_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;   // Convert nanoseconds to milliseconds

    printf("All tasks completed in " ANSI_RED "%.2f" ANSI_RESET " seconds!\n", total_time);

    return 0;
}
