#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

char * not_allowed = "/bin/sh";

void give_date() {
    system("/bin/date");
}

void vuln() {
    char password[16];
    puts("What is the password: ");
    scanf("%s", password);
    if (strcmp(password, "31337h4x") == 0) {
        puts("Correct password!");
        give_date();
    }
    else {
        puts("Incorrect password!");
    }
}

int main() {
    vuln();
}
