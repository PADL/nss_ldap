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
scan_group()
{
        struct group *g;

        setgrent();

        while ((g = getgrent()) != NULL)
        {
		char mem[512];
		char **p;
		int doit = (g->gr_mem[0] != NULL);
		p = g->gr_mem;
		strcpy(mem,"");
		while(doit) {
			if (p != g->gr_mem) strcat(mem, ",");
			strcat(mem, *p);
			if (*(++p) == NULL)
				break;
		}
                printf("%s:%s:%d:%s\n",
			g->gr_name, g->gr_passwd, g->gr_gid, mem);
        }

        endgrent();
}
