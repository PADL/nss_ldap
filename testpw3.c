#include <stdio.h>
#include <pwd.h>

void main(int argc,char**argv)
{
	scan_passwd();

	exit(0);
}
scan_passwd()
{
        struct passwd p;
	char buf[1024];
	int i = 1;
	FILE *fp = NULL;
	memset(buf, 0xFF, sizeof(buf));

        setpwent_r(&fp);

        while (getpwent_r(&p, buf, (int)sizeof(buf), &fp) == 0)
        {
                printf("%s:%s:%d:%d:%s:%s:%s\n",
                        p.pw_name,
                        p.pw_passwd,
                        p.pw_uid,
                        p.pw_gid,
                        p.pw_gecos,
                        p.pw_dir,
                        p.pw_shell);
		i++;
        }

        endpwent_r(&fp);

	fprintf(stderr, ">>>>>>> %d\n", i);

}
