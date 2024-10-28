#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find a matching hash in the hashFile
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hashPlaintext = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *hashfile = fopen(hashFilename, "r");
    if (!hashfile)
    {
        printf("Couldn't open %s for reading\n", hashFilename);
        exit(1);
    }

    // Loop through the hash file, one line at a time
    char line[HASH_LEN];

    while (fgets(line, HASH_LEN, hashfile) != NULL)
    {
        // trim newline
        char *nl = strrchr(line, '\n');
        if (nl != NULL) *nl = '\0';
            
        // Attempt to match the hash from the file to the hash of the plaintext
        if (strcmp(line, hashPlaintext) == 0)
        {
            fclose(hashfile);
            // return hash if it was found
            return hashPlaintext;
        }
    }        

    // If nothing found, return null
    fclose(hashfile);
    return NULL;
}


int main(int argc, char *argv[])
{
    // check for correct number of arguments
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // Open the dictionary file for reading.
    FILE *dict = fopen(argv[2], "r");
    if (!dict)
    {
        printf("Couldn't open %s for reading\n", argv[2]);
        exit(1);
    }

    // Create string to hold each line in dictionary
    char line[PASS_LEN];
    int count = 0; // match counter

    // For each dictionary word, pass it to tryWord to be hashed
    while (fgets(line, PASS_LEN, dict) != NULL)
    {
        // trim newline
        char *nl = strrchr(line, '\n');
        if (nl != NULL) *nl = '\0';

        // pass in hash and dictionary
        char *match = tryWord(line, argv[1]);

        // If there's a match, display the word and its hash
        if (match)
        {
            // Ex: 5d41402abc4b2a76b9719d911017c592 hello
            printf("%s %s\n", line, match);
            count++;
        }
        free(match); // free malloc memory returned by tryWord
    }
    
    // Close the dictionary file
    fclose(dict);

    // Display the number of hashes that were cracked
    printf("%d hashes cracked!\n", count); 
}