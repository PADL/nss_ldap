/* Define to the number of arguments to ldap_set_rebindproc */
#undef LDAP_SET_REBIND_PROC_ARGS

/* define to the number of args to gethostbyname_r */
#undef GETHOSTBYNAME_R_ARGS

/* define to set RFC2307BIS support */
#undef RFC2307BIS

/* define to enable debug code */
#undef DEBUG

/* define to enable attribute/objectclass mapping */
#undef AT_OC_MAP

/* define to enable proxy authentication for AIX */
#undef PROXY_AUTH

/* define to enable paged results control */
#undef PAGE_RESULTS

/* define to enable configurable Kerberos credentials cache */
#undef CONFIGURE_KRB5_CCNAME

/* define to enable struct ether_addr definition */
#undef HAVE_STRUCT_ETHER_ADDR

/* path to LDAP configuration file */
#define NSS_LDAP_PATH_CONF              "/etc/ldap.conf"

/* path to LDAP root secret file */
#define NSS_LDAP_PATH_ROOTPASSWD        "/etc/ldap.secret"

