#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <minix/mthread.h>

#define HANDLE_ERRORS(msg) handleErrors(__FILE__, __LINE__, msg)
#define KEY_LENGTH 32  // 256 bits
#define IV_LENGTH 16   // 128 bits
#define BUFFER_SIZE 1024 // 1 KB buffer size
#define AES_BLOCK_SIZE 16 // 128 bits
#define HASH_LENGTH SHA256_DIGEST_LENGTH // 32 bytes
#define ADMIN_KEY_FILE "adminKey.bin" // File to store the admin password hash
#define HASH_VALUE_FILE "HashValue.bin" // File to store the hash values of encrypted files

// 32 bytes fixed key and 16 bytes fixed IV
const unsigned char fixed_key[KEY_LENGTH] = "01234567890123456789012345678901"; // 32 bytes fixed key
const unsigned char fixed_iv[IV_LENGTH] = "0123456789012345"; // 16 bytes fixed IV

/**
 * @brief Struct to hold data for thread processing.
 */
typedef struct {
    char *input_filename;  /**< Input filename */
    char *output_filename; /**< Output filename */
    unsigned char key[KEY_LENGTH]; /**< Encryption/Decryption key */
    unsigned char iv[IV_LENGTH]; /**< Initialization Vector */
    int do_encrypt; /**< Flag to indicate whether to encrypt (1) or decrypt (0) */
} ThreadData;

/**
 * @brief Handles errors by printing the error message and exiting the program.
 *
 * @param file The name of the file where the error occurred.
 * @param line The line number where the error occurred.
 * @param msg The error message to print.
 */
void handleErrors(const char *file, int line, const char *msg) {
    printf("Error occurred in file %s at line %d: %s\n", file, line, msg);
    exit(1);
}

/**
 * @brief Computes the SHA-256 hash of a file.
 *
 * @param filename The name of the file to hash.
 * @param hash The buffer to store the computed hash.
 */
void sha256_file(const char *filename, unsigned char *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        HANDLE_ERRORS("Failed to open file for hashing");
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }

    SHA256_Final(hash, &sha256);
    fclose(file);
}

/**
 * @brief Checks if a given hash exists in a file.
 *
 * @param hash The hash to check.
 * @param filename The file containing the list of hashes.
 * @return int 1 if the hash is found, 0 otherwise.
 */
int hash_in_file(const unsigned char *hash, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        HANDLE_ERRORS("Failed to open hash value file");
    }

    char line[HASH_LENGTH * 2 + 1]; // SHA256 hash in hex + null terminator
    unsigned char file_hash[HASH_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        for (int i = 0; i < HASH_LENGTH; ++i) {
            sscanf(&line[i * 2], "%2hhx", &file_hash[i]);
        }
        if (memcmp(hash, file_hash, HASH_LENGTH) == 0) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

/**
 * @brief Saves a hash to a file.
 *
 * @param hash The hash to save.
 * @param filename The file to save the hash to.
 */
void save_hash_to_file(const unsigned char *hash, const char *filename) {
    FILE *file = fopen(filename, "a");
    if (!file) {
        HANDLE_ERRORS("Failed to open hash value file for writing");
    }

    for (int i = 0; i < HASH_LENGTH; ++i) {
        fprintf(file, "%02x", hash[i]);
    }
    fprintf(file, "\n");
    fclose(file);
}

/**
 * @brief Encrypts or decrypts a file based on the provided data.
 *
 * @param data The data required for encryption or decryption.
 */
void encrypt_decrypt_file(ThreadData *data) {
    FILE *input_file = fopen(data->input_filename, "rb");
    FILE *output_file = fopen(data->output_filename, "wb");
    if (!input_file || !output_file) {
        HANDLE_ERRORS("Failed to open input or output file");
    }

    unsigned char iv[IV_LENGTH];
    unsigned char buffer[BUFFER_SIZE];  // buffer for reading data
    unsigned char out_buffer[BUFFER_SIZE + AES_BLOCK_SIZE];  // buffer for output data

    AES_KEY aes_key;
    if (data->do_encrypt) {
        // Generate a random IV and write it to the output file
        if (!RAND_bytes(iv, IV_LENGTH)) {
            HANDLE_ERRORS("Failed to generate random IV");
        }
        fwrite(iv, sizeof(unsigned char), IV_LENGTH, output_file);
        if (AES_set_encrypt_key(data->key, 256, &aes_key) < 0) {
            HANDLE_ERRORS("Failed to set encryption key");
        }
    } else {
        // Read the IV from the input file
        if (fread(iv, sizeof(unsigned char), IV_LENGTH, input_file) != IV_LENGTH) {
            HANDLE_ERRORS("Failed to read IV from input file");
        }
        if (AES_set_decrypt_key(data->key, 256, &aes_key) < 0) {
            HANDLE_ERRORS("Failed to set decryption key");
        }
    }

    int bytes_read;
    int padding = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        if (data->do_encrypt) {
            if (bytes_read < BUFFER_SIZE) {
                // Add padding if it's the last block
                padding = AES_BLOCK_SIZE - (bytes_read % AES_BLOCK_SIZE);
                memset(buffer + bytes_read, padding, padding);
                bytes_read += padding;
            }
            AES_cbc_encrypt(buffer, out_buffer, bytes_read, &aes_key, iv, AES_ENCRYPT);
        } else {
            AES_cbc_encrypt(buffer, out_buffer, bytes_read, &aes_key, iv, AES_DECRYPT);
            if (feof(input_file)) {
                // Check if it is the last block for decryption
                padding = out_buffer[bytes_read - 1];
                bytes_read -= padding;
            }
        }
        if (fwrite(out_buffer, 1, bytes_read, output_file) != bytes_read) {
            HANDLE_ERRORS("Failed to write to output file");
        }
        memset(buffer, 0, sizeof(buffer));  // clear buffer after processing
        memset(out_buffer, 0, sizeof(out_buffer));  // clear output buffer after processing
    }

    if (ferror(input_file) || ferror(output_file)) {
        HANDLE_ERRORS("Error occurred during file read/write");
    }

    fclose(input_file);
    fclose(output_file);

    // Print success message based on operation
    if (data->do_encrypt) {
        printf("File '%s' has been encrypted successfully.\n", data->input_filename);
        // compute and save hash value of the encrypted file
        unsigned char hash[HASH_LENGTH];
        sha256_file(data->output_filename, hash);
        save_hash_to_file(hash, HASH_VALUE_FILE);
    } else {
        // verify hash value of the decrypted file
        unsigned char hash[HASH_LENGTH];
        sha256_file(data->input_filename, hash);
        if (hash_in_file(hash, HASH_VALUE_FILE)) {
            printf("File '%s' has been decrypted successfully.\n", data->input_filename);
        } else {
            printf("Hash value of file '%s' not found. Continue decryption? (y/n): ", data->input_filename);
            char choice;
            scanf(" %c", &choice);
            if (choice == 'y' || choice == 'Y') {
                printf("File '%s' has been decrypted successfully.\n", data->input_filename);
            } else {
                printf("Decryption of file '%s' aborted.\n", data->input_filename);
                remove(data->output_filename);  // delete the decrypted file
            }
        }
    }
}

/**
 * @brief Thread function for encrypting or decrypting a file.
 *
 * @param arg Pointer to the ThreadData structure.
 * @return void* Always returns NULL.
 */
void *thread_func(void *arg) {
    ThreadData *data = (ThreadData *) arg;
    encrypt_decrypt_file(data);
    return NULL;
}

/**
 * @brief Constructs the output filename based on the input filename and the operation (encrypt/decrypt).
 *
 * @param output_filename The buffer to store the output filename.
 * @param input_filename The input filename.
 * @param do_encrypt Flag indicating whether to encrypt (1) or decrypt (0).
 */
void construct_output_filename(char *output_filename, const char *input_filename, int do_encrypt) {
    const char *ext = do_encrypt ? ".encrypted" : ".decrypted";
    snprintf(output_filename, strlen(input_filename) + strlen(ext) + 1, "%s%s", input_filename, ext);
}

/**
 * @brief Computes the SHA-256 hash of a string.
 *
 * @param str The string to hash.
 * @param len The length of the string.
 * @param hash The buffer to store the computed hash.
 */
void sha256(const char *str, size_t len, unsigned char *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, len);
    SHA256_Final(hash, &sha256);
}

/**
 * @brief Verifies the password by comparing its hash with the stored hash in the admin key file.
 *
 * @param password The password to verify.
 * @return int 1 if the password is correct, 0 otherwise.
 */
int verify_password(const char *password) {
    unsigned char hash[HASH_LENGTH];
    sha256(password, strlen(password), hash);

    FILE *file = fopen(ADMIN_KEY_FILE, "rb");
    if (!file) {
        HANDLE_ERRORS("Failed to open admin key file");
    }

    unsigned char stored_hash[HASH_LENGTH];
    fread(stored_hash, 1, HASH_LENGTH, file);
    fclose(file);

    return memcmp(hash, stored_hash, HASH_LENGTH) == 0;
}

/**
 * @brief Sets the admin password by storing its hash in the admin key file.
 *
 * @param password The password to set.
 */
void set_password(const char *password) {
    unsigned char hash[HASH_LENGTH];
    sha256(password, strlen(password), hash);

    FILE *file = fopen(ADMIN_KEY_FILE, "wb");
    if (!file) {
        HANDLE_ERRORS("Failed to open admin key file for writing");
    }

    fwrite(hash, 1, HASH_LENGTH, file);
    fclose(file);
}

/**
 * @brief Lists the files available for encryption or decryption.
 *
 * @param files The buffer to store the file names.
 * @param num_files The number of files found.
 * @param encrypt Flag indicating whether to list files for encryption (1) or decryption (0).
 */
void list_files(char ***files, int *num_files, int encrypt) {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (!d) {
        HANDLE_ERRORS("Failed to open current directory");
    }

    *num_files = 0;
    *files = NULL;

    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {
            int len = strlen(dir->d_name);
            if ((encrypt && (len < 10 || strcmp(dir->d_name + len - 10, ".encrypted") != 0)) ||
                (!encrypt && len >= 10 && strcmp(dir->d_name + len - 10, ".encrypted") == 0)) {
                *files = realloc(*files, (*num_files + 1) * sizeof(char *));
                (*files)[*num_files] = strdup(dir->d_name);
                (*num_files)++;
            }
        }
    }
    closedir(d);
}

/**
 * @brief Processes the user command to encrypt or decrypt files.
 *
 * @param encrypt Flag indicating whether to encrypt (1) or decrypt (0).
 */
void process_command(int encrypt) {
    char **files;
    int num_files;
    list_files(&files, &num_files, encrypt);

    if (num_files == 0) {
        printf("No files available for %s.\n", encrypt ? "encryption" : "decryption");
        return;
    }

    printf("Available files for %s:\n", encrypt ? "encryption" : "decryption");
    for (int i = 0; i < num_files; i++) {
        printf("%d: %s\n", i + 1, files[i]);
    }

    char input[256];
    int selected_files[256];
    int count = 0;

    while (1) {
        printf("Enter the numbers of the files to %s (separated by spaces): ", encrypt ? "encrypt" : "decrypt");
        fgets(input, sizeof(input), stdin);

        char *token = strtok(input, " ");
        count = 0;
        int valid_input = 1;

        while (token != NULL) {
            if (*token == '\n' || *token == '\0') {
                break;
            }
            int index = atoi(token) - 1;
            if (index < 0 || index >= num_files) {
                valid_input = 0;
                break;
            }
            selected_files[count++] = index;
            token = strtok(NULL, " ");
        }

        if (valid_input && count > 0) {
            break;
        } else {
            printf("Invalid input. Please enter valid numbers separated by spaces.\n");
        }
    }

    ThreadData *data = malloc(count * sizeof(ThreadData));
    mthread_thread_t *threads = malloc(count * sizeof(mthread_thread_t));

    for (int i = 0; i < count; i++) {
        int index = selected_files[i];
        data[i].input_filename = files[index];
        data[i].output_filename = malloc(strlen(files[index]) + 11);  // 11 for ".encrypted" or ".decrypted"
        construct_output_filename(data[i].output_filename, files[index], encrypt);
        memcpy(data[i].key, fixed_key, KEY_LENGTH);
        memcpy(data[i].iv, fixed_iv, IV_LENGTH);
        data[i].do_encrypt = encrypt;
        if (mthread_create(&threads[i], NULL, thread_func, &data[i]) != 0) {
            HANDLE_ERRORS("Failed to create thread");
        }
    }

    for (int i = 0; i < count; i++) {
        if (mthread_join(threads[i], NULL) != 0) {
            HANDLE_ERRORS("Failed to join thread");
        }
        free(data[i].output_filename);
    }

    free(data);
    free(threads);

    for (int i = 0; i < num_files; i++) {
        free(files[i]);
    }
    free(files);
}

int main() {
    // check if admin key file exists
    FILE *admin_key_file = fopen(ADMIN_KEY_FILE, "rb");
    if (admin_key_file) {
        // check if the file is empty
        fseek(admin_key_file, 0, SEEK_END);
        long file_size = ftell(admin_key_file);
        fclose(admin_key_file);

        if (file_size == 0) {
            // Check if the file is empty and prompt user to set a new password
            char password[256];
            printf("Set a new admin password: ");
            scanf("%255s", password);
            set_password(password);
            printf("Password set successfully.\n");
        } else {
            // File exists and is not empty, prompt user to enter password
            while (1) {
                char password[256];
                printf("Enter admin password: ");
                scanf("%255s", password);
                if (verify_password(password)) {
                    printf("Password verified. Access granted.\n");
                    break;
                } else {
                    printf("Incorrect password. Try again.\n");
                }
            }
        }
    } else {
        // Admin key file does not exist, prompt user to set a new password
        char password[256];
        printf("Set a new admin password: ");
        scanf("%255s", password);
        set_password(password);
        printf("Password set successfully.\n");
    }

    while (1) {
        char command[10];
        printf("Enter command (encrypt/decrypt) or 'exit' to quit: ");
        scanf("%9s", command);
        while (getchar() != '\n');  // clear input buffer

        if (strcmp(command, "exit") == 0) {
            break;
        } else if (strcmp(command, "encrypt") == 0) {
            process_command(1);
        } else if (strcmp(command, "decrypt") == 0) {
            process_command(0);
        } else {
            printf("Invalid command. Please enter 'encrypt', 'decrypt', or 'exit'.\n");
        }
    }

    return 0;
}
