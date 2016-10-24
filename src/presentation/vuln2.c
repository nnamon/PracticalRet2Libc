#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void give_shell() {
    system("/bin/sh");
}

void vuln() {
    char password[16];
    puts("What is the password: ");
    scanf("%s", password);
    if (strcmp(password, "31337h4x") == 0) {
        puts("Correct password!");
        give_shell();
    }
    else {
        puts("Incorrect password!");
    }
}

int main() {
    vuln();
}
