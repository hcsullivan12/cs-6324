#include "stdio.h"

int func(char *user) {
    fprintf( stdout, user );
    return 0;
}

int main() {
    func("%s%s");
    return 0;
}
