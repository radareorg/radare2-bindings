#include <stdio.h>
main() {
	int res = snprintf (NULL, -1, "%s/%s", "foo", "bar");
	res++;
	char *buf = malloc(res);
	int res2 = snprintf (buf, res, "%s/%s", "foo", "bar");
printf ("%d\n", res2);	
	printf ("%s\n", buf);
}
