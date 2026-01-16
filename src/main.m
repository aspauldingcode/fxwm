#import <Foundation/Foundation.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <libkern/OSByteOrder.h>
#include <sys/types.h>
#include <dirent.h>
#include <termios.h>

int patchy();

void main(void) {
    patchy();
}
