#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <dirent.h>
#include <stddef.h>
#include <pwd.h>

/*
 * Copyright (c) 2014,2015 Monica Dunlap
 *
 * This program can be distributed under the terms of the GNU GPL.
 *
 * This implements a functional mostly null file systems. Files written to exist but are empty. Directory structure is maintained.
 *   This is achieved by using the an OS file system for the "INODE" table. The only real costs are in inodes and whatever
 *   blocks are required to maintain directory tables.
 *
 * By default this is a "translucent/overlay" mount over top of the target mount point. What was there is still visible. Anything
 *   added will still be there when unmounted (but empty). Anything removed WILL BE GONE!
 * By default files are created as sparse files. This means the `ls(1)` size is not their real size. `du` them instead.
 * Any files that were already there will still be there but appear empty when a read attempt occurs.
 *
 * Non-fuse options:
 *  --debug | -o debug -- Turns on nullfs debugging. * Not to be confused with fuse's -d option which turns this on too.
 *  -o nosparse        -- Turns off sparse file creation. All files will be 0 bytes instead regardless of how much is written.
 *  -o username=<name> -- Set the running process to username.  I.E. -o username=nobody will run as user nobody.
 *  -o inode_dir=<dir> -- Set the directory used for the FS structure instead of the mount point. Turns off "translucent" mode.
 *                        ** Note that anything already in <dir> will now be in the mount point.
 *
 * It is known to work under (CentOS/RHEL 5 6 7 and Fedora 20)
 *
 * Notes:
 * fuse_daemonize() unhelpfully does a chdir("/") in background mode. nullfs_daemonize() was created to do the backgrounding
 * fuse_parse_cmdline() removes the mountpoint (and -f if set) from args so it is put back.
 * This forces -f -o default_permissions,nonempty,big_writes on fuse_main(); whether you set it or not.
 *
 */

/*
#define DEBUG(fmt, ...) 
*/
#define DEBUG(fmt, ...) if(nullfs.debug) fprintf(stderr,fmt,##__VA_ARGS__);

struct nullfs_s
{
  int savefd;
  int debug;
  int sparse_set;
  int multithreaded;
  int foreground;
  char *mountpoint;
  char *inode_dir;
  char *username;
};
static struct nullfs_s nullfs;

static int nullfs_getattr(const char *path, struct stat *stbuf)
{
  int r;

  if (! path)
    return -ENOENT;

  DEBUG("nullfs_getattr(%s)\n",path);

  if(path[1] == 0)
    r = lstat(".",stbuf);
  else
    r = lstat((path + 1),stbuf);

  if(r != 0)
    return -ENOENT;
  else
    return(0);
};

static int nullfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
  (void) offset;
  (void) fi;
  DIR *dir_fd;
  struct dirent *my_dirent;

  DEBUG("nullfs_readdir(%s)\n",path);

  if(path[1] == 0)
    dir_fd = opendir(".");
  else
    dir_fd = opendir((path + 1));

  if(!dir_fd)
    return -ENOENT;
  while(my_dirent = readdir(dir_fd))
    filler(buf, my_dirent->d_name, NULL, 0);
  closedir(dir_fd);

  return 0;
};

static int nullfs_mkdir(const char *path, mode_t mode)
{
  (void) path;
  (void) mode;
  int r;

  DEBUG("nullfs_mkdir(%s)\n",path);

  r = mkdir((path + 1),mode);
  if(r == 0)
    lchown((path + 1), fuse_get_context()->uid, fuse_get_context()->gid);

  return(r);
}

static int nullfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  (void) fi;
  int r;
  int fh;

  DEBUG("nullfs_create(%s)\n",path);

  fh = open((path + 1),fi->flags,mode);
  if(fh == -1)
    return(-errno);

  lchown((path + 1), fuse_get_context()->uid, fuse_get_context()->gid);
  if(nullfs.sparse_set)
    fi->fh = fh;
  else
    close(fh);

  return 0;
};

static int nullfs_open(const char *path, struct fuse_file_info *fi)
{
  (void) fi;
  uint64_t fh;

  DEBUG("nullfs_open(%s)\n",path);

  /* should be pointless since / is a directory and _open should not be called.. Eh, checking anyway */
  if(path[1] == 0)
    return(-ENOENT);

  fh = open((path + 1),fi->flags);
  if(fh == -1)
    return(-errno);

  if(nullfs.sparse_set)
    fi->fh = fh;
  else
    close(fh);

  return 0;
};

static int nullfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  (void) buf;
  (void) size;
  (void) offset;
  (void) fi;

  DEBUG("nullfs_read(%s)\n",path);

  return 0;
};

static int nullfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  (void) buf;
  (void) offset;
  (void) fi;

  DEBUG("nullfs_write(%s,size:%d,offset:%d)\n",path,size,offset);

  if(fi->fh && nullfs.sparse_set)
  {
    DEBUG("nullfs_write(%s) ftruncate(%d)\n",path,(size+offset));
    ftruncate(fi->fh,size+offset);
  }

  return (int) size;
};

static int nullfs_release(const char *path, struct fuse_file_info *fi)
{
  (void) path;
  (void) fi;

  DEBUG("nullfs_release(%s)\n",path);

  if(fi->fh)
  {
    close(fi->fh);
    fi->fh = -1;
  }

  return(0);
}

static int nullfs_flush(const char *path, struct fuse_file_info *fi)
{
  (void) path;
  (void) fi;

  DEBUG("nullfs_flush(%s)\n",path);

  return(0);
}

static int nullfs_unlink(const char *path)
{
  (void) path;
  char *this_path;

  DEBUG("nullfs_unlink(%s)\n",path);

  if(path[1] == 0)
    return(-ENOENT);

  unlink((path + 1));

  return 0;
};

static int nullfs_rmdir(const char *path)
{
  (void) path;
  char *this_path;
  int r;

  DEBUG("nullfs_rmdir(%s)\n",path);

  if(path[1] == 0)
    return(-ENOENT);

  r = rmdir((path + 1));

  return(r);
};

static int nullfs_rename(const char *src, const char *dst)
{
  (void) src;
  (void) dst;
  int r;

  DEBUG("nullfs_rename(%s,%s)\n",src,dst);

  r = rename((src + 1),(dst + 1));

  return(r);
};

static int nullfs_truncate(const char *path, off_t offset)
{
  (void) path;
  (void) offset;

  DEBUG("nullfs_truncate(%s,%d)\n",path,offset);

  if(path[1] == 0)
    return(-ENOENT);

  return(truncate((path +1),offset));
};

static int nullfs_chmod(const char *path, mode_t mode)
{
  (void) path;
  (void) mode;
  int r;

  DEBUG("nullfs_chmod(%s,%o)\n",path,mode);

  if(path[1] == 0)
    r = chmod(".",mode);
  else
    r = chmod((path + 1),mode);

  return(r);
};

static int nullfs_statfs(const char *path, struct statvfs *sfs)
{
  (void) path;
  (void) sfs;

  DEBUG("nullfs_statfs(%s)\n",path);

  statvfs(".",sfs);

  return(0);
}

static int nullfs_chown(const char *path, uid_t u, gid_t g)
{
  (void) path;
  (void) u;
  (void) g;
  int r;

  DEBUG("nullfs_chown(%s)\n",path);

  if(path[1] == 0)
    r = chown(".",u,g);
  else
    r = chown((path + 1),u,g);

  return(0);
};

static int nullfs_link(const char *oldpath, const char *newpath)
{
  int r;

  DEBUG("nullfs_link('%s','%s')\n",oldpath,newpath);

  r = link((oldpath + 1),(newpath + 1));

  return(r);
}

static int nullfs_symlink(const char *oldpath, const char *newpath)
{
  int r;
  DEBUG("nullfs_symlink('%s','%s')\n",oldpath,newpath);
  newpath++;

  DEBUG("symlink('%s','%s')\n",oldpath,newpath);
  r = symlink(oldpath,newpath);

  if(r == 0)
    lchown(newpath, fuse_get_context()->uid, fuse_get_context()->gid);

  return(r);
}

static int nullfs_readlink(const char *path1, char *buf, size_t buf_size)
{
  ssize_t r;

  DEBUG("nullfs_readlink('%s')\n",path1);

  r = readlink((path1 + 1), buf, buf_size);
  if(r == -1)
    return(errno);
  else if(r != buf_size)
    buf[r] = 0;
  
  DEBUG("nullfs_readlink returned %d\n",r);
  DEBUG("nullfs_readlink returned buf=%s\n",buf);
  DEBUG("nullfs_readlink returned buf_size=%d\n",buf_size);

  return(0);
}

static int nullfs_utimens(const char *path, const struct timespec ts[2])
{
  (void) path;
  (void) ts;
  int r;
  struct timeval tv[2];

  DEBUG("nullfs_utimens(%s)\n",path);

  if(path[1] == 0)
    return(-ENOENT);

  tv[0].tv_sec = ts[0].tv_sec;
  tv[0].tv_usec = ts[0].tv_nsec / 1000;
  tv[1].tv_sec = ts[1].tv_sec;
  tv[1].tv_usec = ts[1].tv_nsec / 1000;

  r = utimes((path + 1), tv);
  if (r == -1)
    return -errno;

  return 0;
};

/*
 * demonize current process by forking it and killing the parent.  This makes current process as a child of 'init'.
 * stolen directly from fuse-2.9.3/lib/helper.c without the presumption of chdir();
 */
int nullfs_daemonize()
{
  int nullfd;

  switch(fork()) {
  case -1:
    perror("fuse_daemonize: fork");
    return -1;
  case 0:
    break;
  default:
    exit(0);
  }

  if (setsid() == -1) {
    perror("fuse_daemonize: setsid");
    return -1;
  }

  nullfd = open("/dev/null", O_RDWR, 0);
  if (nullfd != -1)
  {
    (void) dup2(nullfd, 0);
    (void) dup2(nullfd, 1);
    (void) dup2(nullfd, 2);
    if (nullfd > 2)
      close(nullfd);
  }
  return 0;
}

static struct fuse_operations nullfs_oper =
{
    .getattr    = nullfs_getattr,
    .readdir    = nullfs_readdir,
    .mkdir      = nullfs_mkdir,
    .open       = nullfs_open,
    .read       = nullfs_read,
    .write      = nullfs_write,
    .flush      = nullfs_flush,
    .release    = nullfs_release,
    .create     = nullfs_create,
    .unlink     = nullfs_unlink,
    .rmdir      = nullfs_rmdir,
    .truncate   = nullfs_truncate,
    .rename     = nullfs_rename,
    .chmod      = nullfs_chmod,
    .chown      = nullfs_chown,
    .utimens    = nullfs_utimens,
    .statfs     = nullfs_statfs,
    .link       = nullfs_link,
    .symlink    = nullfs_symlink,
    .readlink   = nullfs_readlink,
};

int main(int argc, char **argv)
{
  int c;
  unsigned char default_permissions_set = 0;
  unsigned char nonempty_set = 0;
#ifdef FUSE_CAP_BIG_WRITES
  unsigned char big_writes_set = 0;
#endif
  struct passwd *user_pwent;

  nullfs.debug = 0;
  nullfs.sparse_set = 1;
  nullfs.username = (char *)NULL;
  nullfs.inode_dir = (char *)NULL;
  nullfs.mountpoint = (char *)NULL;

  static struct fuse_opt nullfs_opts[] =
  {
    { "--debug", offsetof(struct nullfs_s,debug) , 0 },
    { "debug", offsetof(struct nullfs_s,debug) , 0 },
    { "nosparse", offsetof(struct nullfs_s,sparse_set) , 0 },
    { "username=%s", offsetof(struct nullfs_s,username) , 0 },
    { "inode_dir=%s", offsetof(struct nullfs_s,inode_dir) , 0 },
  };

  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  fuse_opt_parse(&args, &nullfs, nullfs_opts, NULL);

  /* Look for what has been set and force them if not. */
  for(c=0;c<argc;c++)
  {
    if(strstr(argv[c],"default_permissions") != NULL)
      default_permissions_set = 1;
    if(strstr(argv[c],"nonempty") != NULL)
      nonempty_set = 1;
#ifdef FUSE_CAP_BIG_WRITES
    if(strstr(argv[c],"big_writes") != NULL)
      big_writes_set = 1;
#endif
    if(strstr(argv[c],"-d") != NULL)
      nullfs.debug = 1;
    if(strstr(argv[c],"-f") != NULL)
      nullfs.debug = 1;
  }

  if(default_permissions_set == 0)
    fuse_opt_add_arg(&args,"-odefault_permissions");
  if(!nonempty_set)
    fuse_opt_add_arg(&args,"-ononempty");
#ifdef FUSE_CAP_BIG_WRITES
  if(!big_writes_set)
    fuse_opt_add_arg(&args,"-obig_writes");
#endif

  fuse_parse_cmdline(&args,&nullfs.mountpoint,&nullfs.multithreaded,&nullfs.foreground);

  if(nullfs.mountpoint == NULL)
  {
    fputs("Mountpoint not set. Cowardly exiting.\n",stderr);
    exit(1);
  }

  /* Have to force put back -f and the mountpoint that fuse_parse_cmdline() removed */
  fuse_opt_add_arg(&args,"-f");
  fuse_opt_add_arg(&args,nullfs.mountpoint);

  for(c=0;c<args.argc;c++)
  {
    DEBUG("argv[%d] = %s\n",c,args.argv[c]);
  }

  DEBUG("---->sparse_set: %d\n",nullfs.sparse_set);
  DEBUG("---->mountpoint: %s\n",nullfs.mountpoint);
  DEBUG("---->multithreaded: %d\n",nullfs.multithreaded);
  DEBUG("---->foreground: %d\n",nullfs.foreground);
  DEBUG("---->username: %d\n",nullfs.username);
  DEBUG("---->inode_dir: %d\n",nullfs.inode_dir);

  if(nullfs.inode_dir)
  {
    DEBUG("chdir(\"%s\")\n",nullfs.inode_dir);
    c = chdir(nullfs.inode_dir);
  }
  else
  {
    DEBUG("chdir(\"%s\")\n",nullfs.mountpoint);
    c = chdir(nullfs.mountpoint);
  }

  if(c != 0)
  {
    fprintf(stderr,"Could not chdir()\n");
    exit(1);
  }
  DEBUG("cwd: %s\n",get_current_dir_name());

  nullfs.savefd = open(".",0);

  if(nullfs.username)
  {
    user_pwent = getpwnam(nullfs.username);
    if(user_pwent == NULL)
    {
      printf("-o username=%s: getpwnam() failed\n",nullfs.username);
      exit(1);
    }
    DEBUG("Changing to uid:%d GID:%d\n",user_pwent->pw_uid,user_pwent->pw_gid);
    setegid(user_pwent->pw_gid);
    setgid(user_pwent->pw_gid);
    seteuid(user_pwent->pw_uid);
    setuid(user_pwent->pw_uid);
  }

  if(nullfs.foreground == 0 && nullfs_daemonize() != 0)
    exit(1);

  return fuse_main(args.argc, args.argv, &nullfs_oper, NULL);
};

