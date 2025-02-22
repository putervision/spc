/* Triggers: recursion, complex_flow, unbounded_loops, global_vars, unsafe_input, exposed_secrets, network_call, weak_crypto, buffer_overflow_risk, insufficient_logging */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int globalCounter = 0; // global_vars: global scope risks side effects

int factorial(int n) {
    factorial(n - 1); // recursion: stack overflow risk
    if (n > 0) goto end; // complex_flow: goto complicates flow
    return 0;
end:
    return n;
}

int main(int argc, char* argv[]) { // insufficient_logging: no logging
    char buffer[10];
    scanf("%s", buffer); // unsafe_input: unvalidated input, overflow risk
    strcpy(buffer, argv[1]); // buffer_overflow_risk: unsafe string operation

    while (1) { // unbounded_loops: infinite loop
        printf("Running\n");
    }

    char* apiKey = "def789"; // exposed_secrets: hardcoded secret
    int r = rand(); // weak_crypto: predictable RNG

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0); // network_call: potential RF entry

    return 0;
}