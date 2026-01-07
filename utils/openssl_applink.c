#ifdef _WIN32
/*
 * Local copy of OpenSSL applink.c to satisfy Windows/MinGW builds.
 * This file is derived from OpenSSL's applink.c (public domain-like).
 */

# define APPLINK_STDIN   1
# define APPLINK_STDOUT  2
# define APPLINK_STDERR  3
# define APPLINK_FPRINTF 4
# define APPLINK_FGETS   5
# define APPLINK_FREAD   6
# define APPLINK_FWRITE  7
# define APPLINK_FSETMOD 8
# define APPLINK_FEOF    9
# define APPLINK_FCLOSE  10
# define APPLINK_FOPEN   11
# define APPLINK_FSEEK   12
# define APPLINK_FTELL   13
# define APPLINK_FFLUSH  14
# define APPLINK_FERROR  15
# define APPLINK_CLEARERR 16
# define APPLINK_FILENO  17
# define APPLINK_OPEN    18
# define APPLINK_READ    19
# define APPLINK_WRITE   20
# define APPLINK_LSEEK   21
# define APPLINK_CLOSE   22
# define APPLINK_MAX     22

# include <stdio.h>
# include <stdarg.h>
# include <io.h>
# include <fcntl.h>
# include <windows.h>

static void *app_stdin(void)  { return stdin; }
static void *app_stdout(void) { return stdout; }
static void *app_stderr(void) { return stderr; }
static int   app_feof(FILE *fp) { return feof(fp); }
static int   app_ferror(FILE *fp) { return ferror(fp); }
static void  app_clearerr(FILE *fp) { clearerr(fp); }
static int   app_fileno(FILE *fp) { return _fileno(fp); }
static int   app_fsetmod(FILE *fp, int mod) { return _setmode(_fileno(fp), mod); }
static FILE *app_fopen(const char *filename, const char *mode) { return fopen(filename, mode); }
static int   app_fclose(FILE *fp) { return fclose(fp); }
static size_t app_fread(void *buf, size_t size, size_t count, FILE *fp) { return fread(buf, size, count, fp); }
static size_t app_fwrite(const void *buf, size_t size, size_t count, FILE *fp) { return fwrite(buf, size, count, fp); }
static int   app_fseek(FILE *fp, long off, int whence) { return fseek(fp, off, whence); }
static long  app_ftell(FILE *fp) { return ftell(fp); }
static int   app_fflush(FILE *fp) { return fflush(fp); }
static char *app_fgets(char *buf, int size, FILE *fp) { return fgets(buf, size, fp); }
static int   app_fprintf(FILE *fp, const char *fmt, ...) {
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = vfprintf(fp, fmt, args);
    va_end(args);
    return ret;
}

static int   app_open(const char *fn, int flags, int mode) { return _open(fn, flags, mode); }
static int   app_close(int fd) { return _close(fd); }
static int   app_read(int fd, void *buf, unsigned int len) { return _read(fd, buf, len); }
static int   app_write(int fd, const void *buf, unsigned int len) { return _write(fd, buf, len); }
static long  app_lseek(int fd, long off, int whence) { return _lseek(fd, off, whence); }

__declspec(dllexport) void **OPENSSL_Applink(void)
{
    static void *OPENSSL_ApplinkTable[APPLINK_MAX + 1] = {
        (void *)APPLINK_MAX,
        (void *)app_stdin, (void *)app_stdout, (void *)app_stderr,
        (void *)app_fprintf, (void *)app_fgets, (void *)app_fread,
        (void *)app_fwrite, (void *)app_fsetmod, (void *)app_feof,
        (void *)app_fclose, (void *)app_fopen, (void *)app_fseek,
        (void *)app_ftell, (void *)app_fflush, (void *)app_ferror,
        (void *)app_clearerr, (void *)app_fileno, (void *)app_open,
        (void *)app_read, (void *)app_write, (void *)app_lseek,
        (void *)app_close
    };
    return OPENSSL_ApplinkTable;
}

#endif /* _WIN32 */
