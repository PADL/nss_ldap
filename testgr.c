#include <stdio.h>
#include <grp.h>

void main(int argc,char**argv)
{
#if 0
struct  group { /* see getgrent(3) */
        char    *gr_name;
        char    *gr_passwd;
        gid_t   gr_gid;
        char    **gr_mem;
};
#endif

	scan_group();
	exit(0);
}

void dump(struct group *g)
{
		char mem[2048];
		char **p;

		int doit = (g->gr_mem && *(g->gr_mem));
		p = g->gr_mem;
		strcpy(mem,"");
		while (doit) {
			if (p != g->gr_mem) strcat(mem, ",");
			strcat(mem, *p);
			if (*(++p) == NULL)
				break;
		}
                printf("%s:%s:%d:%s\n",
			g->gr_name, g->gr_passwd, g->gr_gid, mem);

}

scan_group()
{
        struct group *g;


        setgrent();

        while ((g = getgrent()) != NULL)
        {
			dump(g);
        }

        endgrent();

		printf("==> getgrnam(qmail)\n");
		g = getgrnam("qmail");
		if (g != NULL) dump(g);

		printf("==> getgrnam(testgroup)\n");
		g = getgrnam("testgroup");
		if (g != NULL) dump(g);

}
