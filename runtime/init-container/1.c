#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/signalfd.h>

int main() {
  struct signalfd_siginfo siginfo;
  printf("sizeof(signalfd_siginfo): %d\n", sizeof(siginfo));
}
