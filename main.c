#include <stdint.h>
#include <stdlib.h>

int main (void)
{
	volatile unsigned long long i;
	for (i = 0; i < 100000000ULL; ++i) {
		arc4random() % INT32_MAX;
	}
	return 0;
}
