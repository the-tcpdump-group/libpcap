#include <stdio.h>
#include <stdarg.h>

void foo( char* format, ... )
{
    char buffer[256];
    va_list args;
    va_start (args, format);
    vsnprintf (buffer,256,format, args);
}

int main() {
    foo( "%d", 1 );
}
