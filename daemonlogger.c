/* $Id: daemonlogger.c,v 1.21 2008/11/24 19:56:48 roesch Exp $ */

/*************** IMPORTANT DAEMONLOGGER LICENSE TERMS **************** 
* 
* This Daemonlogger software is the copyrighted work of Sourcefire, Inc.
* (C) 2007 Sourcefire, Inc.  All Rights Reserved.  This program is free
* software; you may use, redistribute and/or modify this software only under
* the terms and conditions of the GNU General Public License as published by
* the Free Software Foundation; Version 2 with the clarifications and
* exceptions described below.  If you wish to embed this Daemonlogger
* technology into proprietary software, we sell alternative licenses (contact
* snort-license@sourcefire.com). 
* 
* Note that the GPL requires that any work that contains or is derived from
* any GPL licensed work also must be distributed under the GPL.  However,
* there exists no definition of what is a "derived work."  To avoid
* misunderstandings, we consider an application to constitute a "derivative
* work" for the purpose of this license if it does any of the following: 
* - Integrates source code from Daemonlogger.
* - Includes Daemonlogger copyrighted data files.
* - Integrates/includes/aggregates Daemonlogger into a proprietary executable
*   installer, such as those produced by InstallShield.
* - Links to a library or executes a program that does any of the above where
*   the linked output is not available under the GPL.
* 
* The term "Daemonlogger" should be taken to also include any portions or
* derived works of Daemonlogger.  This list is not exclusive, but is just
* meant to clarify our interpretation of derived works  with some common
* examples.  These restrictions only apply when you actually redistribute
* Daemonlogger.  For example, nothing stops you from writing and selling a
* proprietary front-end to Daemonlogger.  Just distribute it by itself, and
* point people to http://www.snort.org/dl to download Daemonlogger.
* 
* We don't consider these to be added restrictions on top of the GPL, but just
* a clarification of how we interpret "derived works" as it applies to our
* GPL-licensed Snort product.  This is similar to the way Linus Torvalds has
* announced his interpretation of how "derived works" applies to Linux kernel
* modules.  Our interpretation refers only to Daemonlogger - we don't speak
* for any other GPL products.
* 
* If you have any questions about the GPL licensing restrictions on using
* Daemonlogger in non-GPL works, we would be happy to help.  As mentioned
* above, we also offer alternative license to integrate Daemonlogger into
* proprietary applications and appliances.  These contracts can generally
* include a perpetual license as well as providing for priority support and
* updates as well as helping to fund the continued development of Daemonlogger
* technology.  Please email snort-license@sourcefire.com for further
* information.
* 
* If you received these files with a written license agreement or contract
* stating terms other than the terms above, then that alternative license
* agreement takes precedence over these comments.
* 
* Source is provided to this software because we believe users have a right to
* know exactly what a program is going to do before they run it. This also
* allows you to audit the software for security holes.
* 
* Source code also allows you to port Daemonlogger to new platforms, fix bugs,
* and add new features.  You are highly encouraged to send your changes to
* roesch@sourcefire.com for possible incorporation into the main distribution.
* By sending these changes to Sourcefire or one of the Sourcefire-moderated
* mailing lists or forums, you are granting to Sourcefire, Inc. the unlimited,
* perpetual, non-exclusive right to reuse, modify, and/or relicense the code.
* Daemonlogger will always be available Open Source, but this is important 
* because the inability to relicense code has caused devastating problems for
* other Free Software projects (such as KDE and NASM).  We also occasionally
* relicense the code to third parties as discussed above.  If you wish to
* specify special license conditions of your contributions, just say so when
* you send them. 
* 
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; including without limitation any implied warranty of 
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
* Public License for more details at http://www.gnu.org/copyleft/gpl.html, 
* or in the COPYING file included with Daemonlogger. 
* 
*/ 

/*
** Copyright (C) 2006 Sourcefire Inc. All Rights Reserved.
** Author: Martin Roesch <roesch@sourcefire.com>
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <limits.h>
#include <dirent.h>
#include <syslog.h>
#include <pcap.h>
#include <dnet.h>
#include <grp.h>
#include <pwd.h>
#include <ctype.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/mount.h>

#ifdef LINUX
#include <sys/statvfs.h>
#include <sys/vfs.h>
#endif

#define SUCCESS     0
#define ERROR       1
#define STDBUF      1024
#define KILOBYTE    (1UL << 10)
#define MEGABYTE    (1UL << 20)
#define GIGABYTE    (1UL << 30)
#define TERABYTE    (1ULL << 40)

#ifndef VERSION
#define VERSION     "1.2.1"
#endif

#define _FILE_OFFSET_BITS   64

#define PRUNE_OLDEST_ABSOLUTE   0
#define PRUNE_OLDEST_IN_RUN     1

/* Fix for broken linux <sys/queue.h> */
#ifndef HAVE_TAILQFOREACH
#define _EVENT_DEFINED_TQENTRY
#define TAILQ_ENTRY(type)                       \
struct {                                \
        struct type *tqe_next;  /* next element */          \
        struct type **tqe_prev; /* address of previous next element */  \
}
#define TAILQ_FIRST(head)       ((head)->tqh_first)
#define TAILQ_END(head)         NULL
#define TAILQ_NEXT(elm, field)      ((elm)->field.tqe_next)
#define TAILQ_FOREACH(var, head, field)                 \
    for((var) = TAILQ_FIRST(head);                  \
        (var) != TAILQ_END(head);                   \
        (var) = TAILQ_NEXT(var, field))
#define TAILQ_INSERT_BEFORE(listelm, elm, field) do {           \
    (elm)->field.tqe_prev = (listelm)->field.tqe_prev;      \
    (elm)->field.tqe_next = (listelm);              \
    *(listelm)->field.tqe_prev = (elm);             \
    (listelm)->field.tqe_prev = &(elm)->field.tqe_next;     \
} while (0)
#endif /* TAILQ_FOREACH */

typedef enum {
    MINUTES=1,
    HOURS,
    DAYS
    } interval;

static char *interval_names[] = {
    "none",
    "minutes",
    "hours",
    "days"
};

typedef enum {
    KILOBYTES = 1,
    MEGABYTES,
    GIGABYTES,
    TERABYTES
    } size;
    
static char *size_names[] = {
    "none",
    "kilobytes",
    "megabytes",
    "gigabytes",
    "terabytes"
};

typedef struct filelist Filelist;

struct file_entry
{
    TAILQ_ENTRY(file_entry) next;
    char *filename;
};

TAILQ_HEAD(filelist, file_entry);

static Filelist file_list;

/* Runtime config struct */
typedef struct _rt_config
{
    int buffer_size;
    int count;
    int daemon_mode;
    int rollover;
    int maxfiles;
    int filecount;
    int showver;
    int datalink;
    int shutdown_requested;
    int restart_requested;
    int ringbuffer;
    int use_syslog;
    int readback_mode;
    int snaplen;
    int drop_privs_flag;
    int chroot_flag;
    int rollover_interval;
    int flush_flag;
    int maxpct;
    int prune_flag;

    char *archivepath;
    char *interface;
    char *retrans_interface;
    char *logpath;
    char *logfilename;
    char *pcap_cmd;
    char *readfile;
    char *true_pid_name;
    char *group_name;
    char *user_name;
    char *chroot_dir;
    char logdir[STDBUF];
    char testpath[STDBUF];

    u_int64_t rollsize;
    time_t lastroll;
    time_t nextroll;
    u_int64_t rollsize_in_blocks;

    pcap_t *pd;
    pcap_dumper_t *pdp;

    eth_t *eth_retrans;

    u_int64_t part_total_blocks;
    u_int64_t part_min_free_blocks;

} rt_config_t;

rt_config_t rt_config;

static char *pidfile = "daemonlogger.pid";
static char *pidpath = "/var/run";

static void (*packet_handler)(char *user, 
                              struct pcap_pkthdr *pkthdr, 
                              u_char *pkt);
static int sniff_loop();
static int set_rollover_time();

#ifdef LINUX
#define d_statfs(p, s) statvfs(p, s)
typedef struct statvfs d_statfs_t; 
#elif MACOSX
#define d_statfs(p, s) statfs64(p, s)
typedef struct statfs64 d_statfs_t;
#else
#define d_statfs(p, s) statfs(p, s)
typedef struct statfs d_statfs_t;
#endif

static void fatal(const char *format, ...)
{
    char buf[STDBUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STDBUF, format, ap);

    if(rt_config.use_syslog)
    {
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "FATAL ERROR: %s", buf);
    }
    else
    {
        fprintf(stderr, "ERROR: %s\n", buf);
        fprintf(stderr,"Fatal Error, Quitting..\n");        
    }

    va_end(ap);

    exit(1);
}

static void msg(const char *format, ...)
{
    char buf[STDBUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STDBUF, format, ap);

    if(rt_config.use_syslog)
    {
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
    }
    else
    {
        fprintf(stderr, "%s\n", buf);
    }
    va_end(ap);
}

static int is_valid_path(char *path)
{
    struct stat st;

    if(path == NULL)
        return 0;
        
    if(stat(path, &st) != 0)
        return 0;

    if(!S_ISDIR(st.st_mode) || access(path, W_OK) == -1)
    {
        return 0;
    }
    return 1;
}

static int create_pid_file(char *path, char *filename)
{
    char filepath[STDBUF];
    char *fp = NULL;
    char *fn = NULL;
    char pid_buffer[12];
    struct flock lock;
    int rval;
    int fd;

    memset(filepath, 0, STDBUF);
    
    if(!filename)
        fn = pidfile;
    else
        fn = filename;
        
    if(!path)
        fp = pidpath;
    else
        fp = path;
    
    if(is_valid_path(fp))
        snprintf(filepath, STDBUF-1, "%s/%s", fp, fn);
    else
        fatal("PID path \"%s\" isn't a writeable directory!", fp);
    
    rt_config.true_pid_name = strdup(filename);
    
    if((fd = open(filepath, O_CREAT | O_WRONLY,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
    {
        return ERROR;
    }

    /* pid file locking */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) == -1)
    {
        if (errno == EACCES || errno == EAGAIN)
        {
            rval = ERROR;
        }
        else
        {
            rval = ERROR;
        }
        close(fd);
        return rval;
    }

    snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int) getpid());
    ftruncate(fd, 0);
    write(fd, pid_buffer, strlen(pid_buffer));
    return SUCCESS;
}


int daemonize()
{
    pid_t pid;
    int fd;

    pid = fork();

    if (pid > 0)
        exit(0); /* parent */

    rt_config.use_syslog = 1;
    if (pid < 0)
        return ERROR;

    /* new process group */
    setsid();

    /* close file handles */
    if ((fd = open("/dev/null", O_RDWR)) >= 0)
    {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) close(fd);
    }

   if (pidfile) return create_pid_file(pidpath, pidfile);
    
    return SUCCESS;
}

char *get_filename()
{
    time_t currtime;

    memset(rt_config.logdir, 0, STDBUF);
    currtime = time(NULL);
    if(rt_config.logpath != NULL)
    {
        if(snprintf(rt_config.logdir, 
                    STDBUF, 
                    "%s/%s.%lu", 
                    rt_config.logpath, 
                    rt_config.logfilename, 
                    (long unsigned int) currtime) < 0)
            return NULL;        
    }
    else
    {
        if(snprintf(rt_config.logdir, 
                    STDBUF, 
                    "%s.%lu",
                    rt_config.logfilename,
                    (long unsigned int) currtime) < 0)
            return NULL;        
    }

    return rt_config.logdir;
}

/*static int go_daemon()
{
    return daemonize();
}
*/
static void dl_shutdown(int signal)
{
    msg("Quitting!");
    if(rt_config.retrans_interface != NULL) 
    {
        eth_close(rt_config.eth_retrans);
    }
    else
    {
        if(rt_config.pdp != NULL)
        {
            pcap_dump_flush(rt_config.pdp);
            pcap_dump_close(rt_config.pdp);
        }
    }
    
    if(rt_config.pd != NULL)
        pcap_close(rt_config.pd);

    if(rt_config.true_pid_name != NULL)
        unlink(rt_config.true_pid_name);
    
    exit(0);
}

static void quitter(int signal)
{
    rt_config.shutdown_requested = 1;
    alarm(1);
}

static int prune_oldest_file_this_run()
{
    struct stat sb;
    struct file_entry *fe;
    
    while((fe = TAILQ_FIRST(&file_list)) != NULL)
    {
        if(fe->filename != NULL)
        {
            if(stat(fe->filename, &sb) != 0)
            {
                msg("[ERR] stat failed for \"%s\": %s\n", fe->filename, 
                    strerror(errno));
                TAILQ_REMOVE(&file_list, fe, next);
                free(fe->filename);
                free(fe);                    
            }
            else
            {
                if((sb.st_mode & S_IFMT) == S_IFREG)
                {
                    msg("[!] Ringbuffer: deleting %s", fe->filename);
                    unlink(fe->filename);
                    TAILQ_REMOVE(&file_list, fe, next);
                    free(fe->filename);
                    free(fe);
                    break;
                }                        
            }
        }
        else
        {
            TAILQ_REMOVE(&file_list, fe, next);
            free(fe);
        }
    }
    
    return 0;
}

static int prune_oldest_file_in_dir()
{
    DIR *dirp;
    struct dirent *dp;
    struct stat sb;
    time_t oldtime = 0;
    char *oldname = NULL;
    char fpath[STDBUF+1];
    
    memset(fpath, 0, STDBUF+1);
    if(rt_config.logpath != NULL)
    {
        dirp = opendir(rt_config.logpath);        
    }
    else
        dirp = opendir(".");
    
    if(dirp == NULL)
    {
        msg("opendir failed\n");
        return 0;
    }
    
    while((dp = readdir(dirp)) != NULL)
    {
        snprintf(fpath, STDBUF, "%s/%s", rt_config.logpath?rt_config.logpath:".", dp->d_name);
        if(stat(fpath, &sb) != 0)
            msg("stat failed for \"%s\": %s\n", fpath, strerror(errno));

        if((sb.st_mode & S_IFMT) == S_IFREG)
        {
            if(strstr(dp->d_name, rt_config.logfilename))
            {
                if(oldtime == 0 || sb.st_mtime < oldtime)
                {
                    oldtime = sb.st_mtime;
                    if(oldname != NULL)
                    {
                        free(oldname);
                    }
                    oldname = strdup(fpath);
                }                                            
            }
        }
    }

    closedir(dirp);
    msg("[!] Ringbuffer: deleting %s", oldname);
    if(*oldname != 0)
        unlink(oldname);
    return 0;
}

static int open_log_file()
{
    struct file_entry *fe;
    char *filepath = get_filename();
    
    if(rt_config.maxfiles == 0 || (rt_config.maxfiles > 0 && rt_config.filecount > 0))
    {
        if(rt_config.maxfiles > 0)
        {
            rt_config.filecount--;
            if(rt_config.ringbuffer == 0)
                msg("%d files to go before quitting", rt_config.filecount+1);
        }
    }
    else
    {
        if(rt_config.ringbuffer == 0)
        {
            msg("Max file count reached, exiting");
            quitter(1);
            return ERROR;            
        }
        else
        {
            if(rt_config.prune_flag == PRUNE_OLDEST_IN_RUN)
                prune_oldest_file_this_run();
            else
                prune_oldest_file_in_dir();
        }
    }
    
    if(rt_config.maxpct != 0)
    {
        d_statfs_t s;
        if(d_statfs(rt_config.testpath, &s) != 0)
        {
            perror("Unable to stat partition!\n");
            fatal("EPIC FAIL!");
        }
        
        if((s.f_bavail - rt_config.rollsize_in_blocks) < rt_config.part_min_free_blocks)
        {
            msg("Disk max utilization reached, rolling over and pruning");
            if(rt_config.prune_flag == PRUNE_OLDEST_IN_RUN)
                prune_oldest_file_this_run();
            else
                prune_oldest_file_in_dir();
        }
    }
    
    if(filepath != NULL)
    {
        if(rt_config.ringbuffer == 1)
        {
            fe = calloc(sizeof(struct file_entry), sizeof(char));
            if((fe->filename = strdup(filepath)) != NULL)
            {
                if(rt_config.prune_flag == PRUNE_OLDEST_IN_RUN)
                    TAILQ_INSERT_TAIL(&file_list, fe, next);
#ifdef DEBUG
                msg("File_list contents:\n");
                TAILQ_FOREACH(fe, &file_list, next)
                {
                    msg("   %s\n", fe->filename);             
                }
#endif
            }
            else
            {
                fatal("Lurene sez ur fucked\n");
            }
        }

        msg("Logging packets to %s", filepath);
        if((rt_config.pdp = pcap_dump_open(rt_config.pd, filepath)) == NULL)
        {
            fatal("Unable to open log file %s\n", pcap_geterr(rt_config.pd));
        }
    }
    else
        return ERROR;

    return SUCCESS;
}

static int drop_privs(void)
{
    struct group *gr;
    struct passwd *pw;
    char *endptr;
    int i;
    int do_setuid = 0;
    int do_setgid = 0;
    unsigned long groupid = 0;
    unsigned long userid = 0;

    if(rt_config.group_name != NULL)
    {
        do_setgid = 1;
        if(isdigit(rt_config.group_name[0]) == 0)
        {
            gr = getgrnam(rt_config.group_name);
            groupid = gr->gr_gid;
        }
        else
        {
            groupid = strtoul(rt_config.group_name, &endptr, 10);
        }        
    }
    
    if(rt_config.user_name != NULL)
    {
        do_setuid = 1;
        do_setgid = 1;
        if(isdigit(rt_config.user_name[0]) == 0)
        {
            pw = getpwnam(rt_config.user_name);
            userid = pw->pw_uid;
        }
        else
        {
            userid = strtoul(rt_config.user_name, &endptr, 10);
            pw = getpwuid(userid);
        }
        
        if(rt_config.group_name == NULL)
            groupid = pw->pw_gid;
    }

    if(do_setgid)
    {
        if((i = setgid(groupid)) < 0)
            fatal("Unable to set group ID: %s", strerror(i));
    }
    
    endgrent();
    endpwent();
    
    if(do_setuid)
    {
        if(getuid() == 0 && initgroups(rt_config.user_name, groupid) < 0)
            fatal("Unable to init group names (%s/%lu)", rt_config.user_name, groupid);
        if((i = setuid(userid)) < 0)
            fatal("Unable to set user ID: %s\n", strerror(i));
    }
    
    return 0;
}

char *get_abs_path(char *dir)
{
    char *savedir, *dirp;

    if(dir == NULL)
    {
        return NULL;
    }

    if((savedir = getcwd(NULL, 0)) == NULL)
    {
        msg("ERROR: getcwd() failed: %s", strerror(errno));
        return NULL;
    }

    if(chdir(dir) < 0)
    {
        msg("ERROR: Can't change to directory: %s\n", dir);
        free(savedir);
        return NULL;
    }

    dirp = getcwd(NULL, 0);
    
    if(chdir(savedir) < 0)
    {
        msg("Can't change back to directory: %s\n", dir);
        free(savedir);                
        return NULL;
    }

    free(savedir);
    return (char *) dirp;
}

static int set_chroot(void)
{
    char *absdir;
    //int abslen = 0;
    //char *logdir = NULL;
    
    //logdir = get_abs_path(rt_config.logpath);

    /* change to the directory */
    if(chdir(rt_config.chroot_dir) != 0)
    {
        fatal("set_chroot: Can not chdir to \"%s\": %s\n", rt_config.chroot_dir, 
              strerror(errno));
    }

    /* always returns an absolute pathname */
    absdir = getcwd(NULL, 0);
    //abslen = strlen(absdir);
    
    /* make the chroot call */
    if(chroot(absdir) < 0)
    {
        fatal("Can not chroot to \"%s\": absolute: %s: %s\n",
               rt_config.chroot_dir, absdir, strerror(errno));
    }

    if(chdir("/") < 0)
    {
        fatal("Can not chdir to \"/\" after chroot: %s\n", 
               strerror(errno));
    }    

    return 0;
}

static int init_retrans()
{
    if((rt_config.eth_retrans = eth_open(rt_config.retrans_interface)) == NULL)
        fatal("init_retrans() eth_open failed\n");
        
    return 0;
}

static int start_sniffing()
{
    bpf_u_int32 localnet, netmask;         /* net addr holders */
    struct bpf_program fcode;              /* Finite state machine holder */
    char errorbuf[PCAP_ERRBUF_SIZE];       /* buffer to put error strings in */
    bpf_u_int32 defaultnet = 0xFFFFFF00;    

    if(rt_config.readback_mode == 0)
    {
        if(rt_config.interface == NULL)
        {
            rt_config.interface = pcap_lookupdev(errorbuf);
            if(rt_config.interface == NULL)
            {
                fatal("start_sniffing() interface lookup: \n\t%s\n", errorbuf);
            }
        }

        msg("sniffing on interface %s", rt_config.interface);
        rt_config.pd = pcap_create(rt_config.interface,
                                   errorbuf);

        if(rt_config.pd == NULL)
        {
            fatal("start_sniffing(): unable to create packet capture handle: %s\n",
                  errorbuf);
        }
        
        if(pcap_set_snaplen(rt_config.pd, rt_config.snaplen?rt_config.snaplen:65535) == 0)
        {
            msg("start_sniffing(): snapshot length option set to %d", rt_config.snaplen?rt_config.snaplen:65535);
        }
        else
        {
            fatal("start_sniffing(): unable to set snaplength option\n");
        }
        
        if(pcap_set_promisc(rt_config.pd, 1) != 0)
        {
            fatal("start_sniffing(): unable to set promiscuous option\n");
        }
        if(pcap_set_timeout(rt_config.pd, 500) != 0)
        {
            fatal("start_sniffing(): unable to set timeout option\n");
        }
        if(pcap_set_buffer_size(rt_config.pd, rt_config.buffer_size?rt_config.buffer_size:2000000) == 0)
        {
            msg("start_sniffing(): buffer size option set to %d", rt_config.buffer_size?rt_config.buffer_size:2000000);
        }
        else
        {
            fatal("start_sniffing(): unable to set packet buffer size option\n");
        }
        
        if(pcap_activate(rt_config.pd) != 0)
        {
            fatal("start_sniffing(): unable to activate packet capture\n");
        }  
    }
    else
    {
        msg("Reading network traffic from \"%s\" file.\n", rt_config.readfile);
        rt_config.pd = pcap_open_offline(rt_config.readfile, errorbuf);
        if(rt_config.pd == NULL)
        {
            fatal("unable to open file \"%s\" for readback: %s\n",
                  rt_config.readfile, errorbuf);
        }

        rt_config.snaplen = pcap_snapshot(rt_config.pd);
        msg("snaplen = %d\n", rt_config.snaplen);
    }

    if(pcap_lookupnet(rt_config.interface, &localnet, &netmask, errorbuf) < 0)
    {
        msg("start_sniffing() device %s network lookup: "
             "\t%s",
             rt_config.interface,
             errorbuf);

        netmask = htonl(defaultnet);
    }

    if(pcap_compile(rt_config.pd, &fcode, rt_config.pcap_cmd, 1, netmask) < 0)
    {
        fatal("start_sniffing() FSM compilation failed: \n\t%s\n"
                "PCAP command: %s\n", pcap_geterr(rt_config.pd), rt_config.pcap_cmd);
    }

    /* set the pcap filter */
    if(pcap_setfilter(rt_config.pd, &fcode) < 0)
    {
        fatal("start_sniffing() setfilter: \n\t%s\n",
                pcap_geterr(rt_config.pd));
    }

    /* get data link type */
    rt_config.datalink = pcap_datalink(rt_config.pd);

    if(rt_config.datalink < 0)
    {
        fatal("OpenPcap() datalink grab: \n\t%s\n",
                pcap_geterr(rt_config.pd));
    }
    return 0;
}

static int log_rollover()
{
    msg("Rolling over logfile...");
    if(rt_config.pdp != NULL)
    {
        pcap_dump_flush(rt_config.pdp);
        pcap_dump_close(rt_config.pdp);
        rt_config.pdp = NULL;
    }
    open_log_file();
    return SUCCESS;
}

static void dl_restart()
{
    rt_config.restart_requested = 0;

    if(rt_config.retrans_interface == NULL)
    {
        pcap_dump_flush(rt_config.pdp);
        pcap_dump_close(rt_config.pdp);
    }
    else
    {
        eth_close(rt_config.eth_retrans);
    }
    
    pcap_close(rt_config.pd);     
    start_sniffing();
    sniff_loop();   
}

static void restarter(int signal)
{
    msg("Caught SIGHUP, restarting...");
    rt_config.restart_requested = 1;
}

static char *load_bpf_file(char *filename)
{
    int fd;
    int readbytes;
    char *filebuf;
    char *comment;
    struct stat buf;
    
    if((fd = open(filename, O_RDONLY)) < 0)
        fatal("Unable to open BPF filter file %s: %s\n", 
              filename, 
              pcap_strerror(errno));
              
    if(fstat(fd, &buf) < 0)
        fatal("Stat failed on %s: %s\n", filename, pcap_strerror(errno));
        
    filebuf = calloc((unsigned int)buf.st_size + 1, sizeof(unsigned char));

    if((readbytes = read(fd, filebuf, (int) buf.st_size)) < 0)
        fatal("Read failed on %s: %s\n", filename, pcap_strerror(errno));
    
    if(readbytes != buf.st_size)
        fatal("Read bytes != file bytes on %s (%d != %d)\n",
              filename, readbytes, (int) buf.st_size);
              
    filebuf[(int)buf.st_size] = '\0';
    close(fd);
    
    /* strip comments and <CR>'s */
    while((comment = strchr(filebuf, '#')) != NULL)
    {
        while(*comment != '\r' && *comment != '\n' && comment != '\0')
        {
            *comment++ = ' ';
        }
    }
    
    return (filebuf);
}

void packet_dump(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
    time_t now;
    
    if(rt_config.rollover)
    {
        now = time(NULL);
        if(rt_config.rollover_interval == 0)
        {
            if(rt_config.lastroll + rt_config.rollover < now)
            {
                msg("Rollover timer has expired!");
                log_rollover();
                rt_config.lastroll = now;    
            }            
        }
        else
        {
            if(now > rt_config.nextroll)
            {
                msg("Rollover timer has expired!");
                log_rollover();
                set_rollover_time();
            }
        }
    }
    
    if(rt_config.shutdown_requested == 1)
        dl_shutdown(0);
    
    if(rt_config.restart_requested == 1)
        dl_restart();

    pcap_dump((u_char *) rt_config.pdp, pkthdr, pkt);
    if(rt_config.flush_flag)
        pcap_dump_flush(rt_config.pdp);
        
    if(((size_t)ftello((FILE *) rt_config.pdp)) > rt_config.rollsize)
    {
        msg("Size limit reached (%zd - %zd = %zd), rolling over!", 
            (size_t)ftell((FILE *) rt_config.pdp), rt_config.rollsize,
            (size_t) ftell((FILE *) rt_config.pdp) - rt_config.rollsize);
        log_rollover();
    }
    
    return;
}

void packet_retrans(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
    eth_send(rt_config.eth_retrans, pkt, pkthdr->caplen);
    
    if(rt_config.shutdown_requested)
        dl_shutdown(0);
    if(rt_config.restart_requested)
        dl_restart();
        
    return;
}

static int sniff_loop()
{
    if(rt_config.chroot_flag)
        set_chroot();

    if(rt_config.retrans_interface != NULL) 
    {
        init_retrans();        
        if(rt_config.drop_privs_flag)
            drop_privs();
    }
    else
    {
        if(rt_config.drop_privs_flag)
            drop_privs();
        open_log_file();        
    }

    rt_config.lastroll = time(NULL);

    /* Read all packets on the device.  Continue until cnt packets read */
    if(pcap_loop(rt_config.pd, rt_config.count, (pcap_handler) packet_handler, NULL) < 0)
    {
        msg("pcap_loop: %s", pcap_geterr(rt_config.pd));

        quitter(1);
    }

    return SUCCESS;
}


char *copy_argv(char **argv)
{
    char **p;
    u_int len = 0;
    char *buf;
    char *src, *dst;
    void ftlerr(char *,...);

    p = argv;
    if(*p == 0)
        return NULL;

    while(*p)
        len += strlen(*p++) + 1;

    buf = (char *) malloc(len);

    if(buf == NULL)
    {
        fatal("malloc() failed: %s\n", strerror(errno));
    }
    p = argv;
    dst = buf;

    while((src = *p++) != NULL)
    {
        while((*dst++ = *src++) != '\0');
        dst[-1] = ' ';
    }

    dst[-1] = '\0';

    return buf;
}

static int set_rollover_time()
{
    time_t now;
    struct tm *curtime;
    
    now = time(NULL);
    curtime = localtime(&now);
    
    switch(rt_config.rollover_interval)
    {
        case MINUTES:
            curtime->tm_min += rt_config.rollover;
            curtime->tm_sec = 0;
            break;
        case HOURS:
            curtime->tm_hour += rt_config.rollover;
            curtime->tm_min = 0;
            curtime->tm_sec = 0;
            break;
        case DAYS:
            curtime->tm_mday += rt_config.rollover;
            curtime->tm_hour = 0;
            curtime->tm_min = 0;
            curtime->tm_sec = 0;
            break;  
    }
    rt_config.nextroll = mktime(curtime);
    return 0;
}


static void usage()
{
    printf("USAGE: daemonlogger [-options] <bpf filter>\n");
    printf("        -a <path>       Set archive directory path to <path>\n");
    printf("        -B <bytes>      Set packet capture buffer size\n");
    printf("        -c <count>      Log <count> packets and exit\n");
    printf("        -d              Daemonize at startup\n");
    printf("        -f <bpf file>   Load BPF filter from <bpf file>\n");
    printf("        -F              Flush the pcap buffer for each packet\n");
    printf("        -g <group name> Set group ID to <group name>\n");
    printf("        -h              Show this usage statement\n");
    printf("        -i <intf>       Grab packets from interface <intf>\n");
    printf("        -l <path>       Log to directory <path>\n");
    printf("        -m <count>      Generate <count> log files and quit\n");
    printf("        -M <pct>        In ringbuffer mode log data to <pct> of\n"
           "                        volume capacity\n");
    printf("        -n <name>       Set output filename prefix to <name>\n");
    printf("        -o <outf>       Disable logging, retransmit data from\n"
           "                        <intf> to <outf>\n");
    printf("        -p <pidfile>    Use <pidfile> for PID filename\n");
    printf("        -P <pidpath>    Use <pidpath> for PID directory\n");
    printf("        -r              Activate ringbuffer mode\n");
    printf("        -R <pcap file>  Read packets from <pcap file>\n");
    printf("        -s <bytes>      Rollover the log file every <bytes>\n");
    printf("        -S <snaplen>    Capture <snaplen> bytes per packet\n");
    printf("        -t <time>       Rollover the log file on time intervals\n");
    printf("        -T <chroot_dir> Set chroot directory to <chroot_dir>\n");
    printf("        -u <user name>  Set user ID to <user name>\n");
    printf("        -v              Show daemonlogger version\n");
    printf("        -z              Delete ringbuffered files from current run only\n");
}

extern char *optarg;
extern int  optind, opterr, optopt;

int parse_cmd_line(int argc, char *argv[])
{
    int ch = 0;
    char rollmetric = 0;
    int rollenum = 0;
    size_t  rollpoint = 0;
    char *endptr = NULL;
    char *bpf_filename = NULL;
    int bpf_file = 0;

    while((ch = getopt(argc, argv, 
            "a:B:c:df:Fg:hi:l:m:M:n:o:p:P:rR:s:S:t:T:u:vz"))!=-1)
    {
        switch(ch)
        {
            case 'a':
                rt_config.archivepath = strdup(optarg);
                break;
            case 'B':
                rt_config.buffer_size = atoi(optarg);
                break;
            case 'c':
                rt_config.count = atoi(optarg);
                break;
            case 'd':
                rt_config.daemon_mode = 1;
                break;
            case 'f':
                bpf_filename = strdup(optarg);
                bpf_file = 1;
                break;
            case 'F':
                rt_config.flush_flag = 1;
                break;
            case 'g':
                rt_config.group_name = strdup(optarg);
                rt_config.drop_privs_flag = 1;
                break;
            case 'h':
                usage();
                exit(0);
                break;
            case 'i':
                rt_config.interface = strdup(optarg);
                break;
            case 'l':
                rt_config.logpath = strdup(optarg);
                break;
            case 'm':
                rt_config.maxfiles = atoi(optarg);
                rt_config.filecount = rt_config.maxfiles;
                break;
            case 'M':
                rt_config.maxpct = atoi(optarg);
                if(rt_config.maxpct > 100 || rt_config.maxpct < 0)
                    fatal("Bad max percent argument: %s\n", optarg);
                break;
            case 'n':
                free(rt_config.logfilename);
                rt_config.logfilename = strdup(optarg);
                break;
            case 'o':
                rt_config.retrans_interface = strdup(optarg);
                packet_handler = packet_retrans;

                break;
            case 'p':
                pidfile = strdup(optarg);
                break;
            case 'P':
                pidpath = strdup(optarg);
                break;
            case 'r':
                rt_config.ringbuffer = 1;
                break;
            case 'R':
                rt_config.readback_mode = 1;
                rt_config.readfile = strdup(optarg);
                break;
            case 's':
                if(isdigit((int)optarg[strlen(optarg)-1]))
                {
                    rt_config.rollsize = strtoul(optarg, &endptr, 10);    
                    if(endptr == optarg)
                    {
                        fprintf(stderr, "Bad rollover size, defaulting to 2GB\n");
                        rt_config.rollsize = 2*GIGABYTE;
                    }
                }
                else
                {
                    sscanf(optarg, "%zu%c", &rollpoint, &rollmetric);
                    
                    switch(tolower(rollmetric))
                    {
                        case 'k':
                            rollenum = KILOBYTES;
                            rt_config.rollsize = rollpoint * KILOBYTE;
                            break;
                        case 'm':
                            rt_config.rollsize = rollpoint * MEGABYTE;
                            rollenum = MEGABYTES;
                            break;
                        case 'g':
                            rt_config.rollsize = rollpoint * GIGABYTE;
                            rollenum = GIGABYTES;
                            break;
                        case 't':
                            rt_config.rollsize = (u_int64_t) rollpoint * TERABYTE;
                            rollenum = TERABYTES;                            
                            break;
                        default:
                            fatal("Bad size argument \"%c\"\n", 
                                  rollmetric);
                            break;
                    }
                }
                break;
            case 'S':
                if(!isdigit(optarg[0]))
                    fatal("Bad snaplen argument \"%s\"\n", optarg);
                rt_config.snaplen = atoi(optarg);
                break;
            case 't':
                if(isdigit((int)optarg[strlen(optarg)-1]))
                {
                     rt_config.rollover = atoi(optarg); 
                }
                else
                {
                    sscanf(optarg, "%d%c", &rt_config.rollover, &rollmetric);
                    
                    switch(tolower(rollmetric))
                    {
                        case 'm':
                            rollenum = MINUTES;
                            rt_config.rollover_interval = MINUTES;
                            break;
                        case 'h':
                            rollenum = HOURS;
                            rt_config.rollover_interval = HOURS;
                            break;
                        case 'd':
                            rollenum = DAYS;
                            rt_config.rollover_interval = DAYS;
                            break;
                        default:
                            fatal("Bad time interval argument \"%c\"\n", 
                                  rollmetric);
                            break;
                    }
                }
                break;
            case 'T':
                rt_config.chroot_dir = strdup(optarg);
                rt_config.chroot_flag = 1;
                break;
            case 'u':
                rt_config.user_name = strdup(optarg);
                rt_config.drop_privs_flag = 1;
                break;
            case 'v':
                rt_config.showver = 1;
                break;
            case 'z':
                rt_config.prune_flag = PRUNE_OLDEST_IN_RUN;
                break;
            default:
                break;          
        }
    }

    if(bpf_file == 0)
        rt_config.pcap_cmd = copy_argv(&argv[optind]);
    else
        rt_config.pcap_cmd = load_bpf_file(bpf_filename);
    
    if(rt_config.ringbuffer == 1 && rt_config.prune_flag == PRUNE_OLDEST_IN_RUN)
        TAILQ_INIT(&file_list);
    
    if(rt_config.archivepath != NULL)
        printf("[-] Archive directory set to %s, ringbuffer mode will archive instead of deleting files.\n", rt_config.archivepath);
    if(rt_config.buffer_size)
        printf("[-] Packet capture buffer set to %d bytes\n", rt_config.buffer_size);
    if(rt_config.count)
        printf("[-] Configured to log %d packets\n", rt_config.count);
    if(rt_config.daemon_mode)
        printf("[-] Daemon mode set\n");
    if(bpf_file)
        printf("[-] Reading BPF filter in from file %s\n", bpf_filename);
    if(rt_config.flush_flag)
        printf("[-] Packet-buffered output activated\n");
    if(rt_config.drop_privs_flag)
        printf("[-] Setting group ID to %s\n", rt_config.group_name);
    if(rt_config.interface != NULL)
        printf("[-] Interface set to %s\n", rt_config.interface);
    if(rt_config.logpath != NULL)
        printf("[-] Logpath set to %s\n", rt_config.logpath);
    if(rt_config.filecount)
        printf("[-] Max files to write set to %d\n", rt_config.maxfiles);
    if(rt_config.logfilename != NULL)
        printf("[-] Log filename set to \"%s\"\n", rt_config.logfilename);
    if(rt_config.retrans_interface != NULL)
        printf("[-] Tap output interface set to %s", rt_config.retrans_interface);
    if(pidfile)
        printf("[-] Pidfile configured to \"%s\"\n", pidfile);
    if(pidpath)
        printf("[-] Pidpath configured to \"%s\"\n", pidpath);
    if(rt_config.ringbuffer)
        printf("[-] Ringbuffer active\n");
    if(rt_config.readback_mode)
        printf("[-] In readback mode\n");
    if(rollpoint != 0)
        printf("[-] Rollover configured for %zu %s\n", 
                rollpoint, size_names[(int)rollenum]);
    else
        printf("[-] Rollover size set to %lu bytes\n", 
                (unsigned long) rt_config.rollsize);
    if(rt_config.snaplen)
        printf("[-] Snaplen set to %d\n", rt_config.snaplen);
    if(rt_config.rollover != 0)
        printf("[-] Rollover metric configured for %d %s\n", 
                rt_config.rollover, interval_names[rt_config.rollover_interval]);
    // else
    //     printf("[-] Rollover time configured for %d seconds\n", 
    //             rt_config.rollover);
    if(rt_config.chroot_flag)
        printf("[-] Setting chroot directory to %s", rt_config.chroot_dir);
    if(rt_config.drop_privs_flag)
        printf("[-] Setting user ID to %s\n", rt_config.user_name);
    if(rt_config.prune_flag == PRUNE_OLDEST_IN_RUN)
        printf("[-] Pruning behavior set to oldest THIS RUN\n");
    else
        printf("[-] Pruning behavior set to oldest IN DIRECTORY\n");

    return SUCCESS;
}

int main(int argc, char *argv[])
{   
    sigset_t set;
    packet_handler = packet_dump;
    int statret;
    d_statfs_t s;
    
    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);

    /* Make this prog behave nicely when signals come along.
     * Windows doesn't like all of these signals, and will
     * set errno for some.  Ignore/reset this error so it
     * doesn't interfere with later checks of errno value.
     */
    signal(SIGTERM, quitter);    if(errno!=0) errno=0;
    signal(SIGINT, quitter);     if(errno!=0) errno=0;
    signal(SIGQUIT, quitter);    if(errno!=0) errno=0;
    signal(SIGHUP, restarter);   if(errno!=0) errno=0;
    signal(SIGALRM, dl_shutdown);  if(errno!=0) errno=0;
    
    memset(&rt_config, 0, sizeof(rt_config_t));

    rt_config.rollsize = 2 * (GIGABYTE);

    rt_config.logfilename = strdup("daemonlogger.pcap");

    parse_cmd_line(argc, argv);

    printf("\n-*> DaemonLogger <*-\n"
           "Version %s\n"
           "By Martin Roesch\n"
           "(C) Copyright 2006-2014 Cisco Systems Inc., All rights reserved\n\n"
           , VERSION);    

    if(rt_config.showver) exit(0);

    if(rt_config.logpath != NULL && !is_valid_path(rt_config.logpath))
        fatal("Log path \"%s\" is bad", rt_config.logpath);
        
    if(rt_config.logpath != NULL)
    {
        snprintf(rt_config.testpath, STDBUF-1, "%s/.", rt_config.logpath);
        msg("Checking partition stats for log directory \"%s\"", rt_config.testpath);
        if((statret = d_statfs(rt_config.testpath, &s)) != 0)
        {
            fatal("Unable to stat partition!\n\"%s\"\n", strerror(statret));
        }
        else
        {
            if(rt_config.maxpct)
            {
                double pct;
                double value;
                
                rt_config.part_total_blocks = s.f_blocks;
                pct = ((double) rt_config.maxpct)/100.0;
                value = ((double)rt_config.part_total_blocks) * pct;
                rt_config.part_min_free_blocks = rt_config.part_total_blocks - ((u_int64_t) value);
                msg("%d%% max disk utilization = %llu blocks free (out of %llu)", 
                    rt_config.maxpct, rt_config.part_min_free_blocks, rt_config.part_total_blocks);
                rt_config.rollsize_in_blocks = (u_int64_t) (rt_config.rollsize/(size_t)s.f_bsize);
                msg("Blocksize = %lu", s.f_bsize);
                msg("Rollsize = %llu blocks\n", rt_config.rollsize_in_blocks);
            }
        }
    }

    if(rt_config.archivepath != NULL && !is_valid_path(rt_config.archivepath))
        fatal("Archive path \"%s\" is bad", rt_config.archivepath);


    if(rt_config.archivepath != NULL)
    {
        memset(rt_config.testpath, 0, STDBUF);
        snprintf(rt_config.testpath, STDBUF-1, "%s/.", rt_config.logpath);
        msg("Checking partition stats for archive directory \"%s\"", rt_config.testpath);
        if((statret = d_statfs(rt_config.testpath, &s)) != 0)
        {
            fatal("Unable to stat partition!\n\"%s\"\n", strerror(statret));
        }
    }

    if(rt_config.daemon_mode) 
    {
        if(!is_valid_path(pidpath))
            fatal("PID path \"%s\" is bad, privilege problem usually",pidpath);
        
        openlog("daemonlogger", LOG_PID | LOG_CONS, LOG_DAEMON);
        daemonize();
    }
    
    start_sniffing();
    if (rt_config.rollover_interval != 0) 
    {
        set_rollover_time();
    }

    sniff_loop();
    return 0;
}
