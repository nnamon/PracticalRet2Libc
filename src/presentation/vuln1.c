#include <stdio.h>

void vuln() {
    char buffer[24];
    gets(buffer);
}

int main() {
    vuln();
}
