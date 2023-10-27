#include <stdint.h>

extern uint32_t arc44random(void);

int main (void)
{
	volatile unsigned long long i;
	for (i = 0; i < 100000000ULL; ++i) {
        arc44random() % INT32_MAX;
	}
	return 0;
}
