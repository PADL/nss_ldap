#include <stdio.h>
#include <pwd.h>
#include <dlfcn.h>

void main(int argc,char**argv)
{
	struct passwd *pw;
	uid_t uid;


	pw = getpwnam(argc > 1 ? argv[1] : "fagen");
	if (!pw) exit(1); 

	printf("%s:%s:%d:%d:%s:%s:%s\n", pw->pw_name,pw->pw_passwd,pw->pw_uid,pw->pw_gid,pw->pw_gecos,pw->pw_dir,pw->pw_shell);	
	uid = pw->pw_uid;

	pw = getpwuid(uid);
	if (!pw) exit(1);

	printf("%s:%s:%d:%d:%s:%s:%s\n", pw->pw_name,pw->pw_passwd,pw->pw_uid,pw->pw_gid,pw->pw_gecos,pw->pw_dir,pw->pw_shell);	

        setpwent();
	scan_passwd();
        endpwent();

	exit(0);
}
scan_passwd()
{
        struct passwd *p;
	int i = 1;


        while ((p = getpwent()) != NULL)
        {
                printf("%s:%s:%d:%d:%s:%s:%s\n",
                        p->pw_name,
                        p->pw_passwd,
                        p->pw_uid,
                        p->pw_gid,
                        p->pw_gecos,
                        p->pw_dir,
                        p->pw_shell);
		i++;
        }
}
