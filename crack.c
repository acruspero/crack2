#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hashPlaintext = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *src = fopen(hashFilename, "r");

    // Loop through the hash file, one line at a time.
    char line[HASH_LEN];

    while (fgets(line, HASH_LEN, src) != NULL)
    {
        // trim newline
        char *nl = strrchr(line, '\n');
        if (nl != NULL) *nl = '\0';
            
        // Attempt to match the hash from the file to the
        // hash of the plaintext.

        // return hash if it was found
        if (strcmp(line, hashPlaintext) == 0)
        {
            fclose(src);
            return hashPlaintext;
        }
    }        

    // Before returning, cleanup
    fclose(src);
    free(hashPlaintext);
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // These two lines exist for testing. When you have
    // tryWord working, it should display the hash for "hello",
    // which is 5d41402abc4b2a76b9719d911017c592.
    // Then you can remove these two lines and complete the rest
    // of the main function below.

    // Open the dictionary file for reading.
    FILE *dict = fopen(argv[2], "r");

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    char line[HASH_LEN];
    int count = 0;
    while (fgets(line, HASH_LEN, dict) != NULL)
    {
        // trim newline
        char *nl = strrchr(line, '\n');
        if (nl != NULL) *nl = '\0';

        // pass in hash and dictionary
        char *match = tryWord(line, argv[1]);

        // If there's a match, display the hash and the word.
        if (match)
        {
            // Ex: 5d41402abc4b2a76b9719d911017c592 hello
            printf("%s %s\n", line, match);
            count++;
        }
        free(match);
    }
    
    // Close the dictionary file.
    fclose(dict);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked!\n", count); 
}

