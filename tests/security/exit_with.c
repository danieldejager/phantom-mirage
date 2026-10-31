/* PM-SCR-195 helper: exits with the status given in argv[1] */
#include <stdlib.h>

int
main(int argc, char **argv)
{
	return (argc > 1 ? atoi(argv[1]) : 0);
}
