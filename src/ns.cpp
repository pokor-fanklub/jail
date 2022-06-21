#include "ns.h"
#include "log.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>

#define SYSC(sys, msg) if(((sys))) {printf("[%m] ");panic((msg));}

namespace jail {

void Namespaces::isolate() {
    // set all next mounts to private
    SYSC(mount(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL), "mount private failed");

    // create jail root directory (only used as mountpoint, no files are being written there)
    if (mkdir(jail_dir_path.c_str(), 0755) < 0 && errno != EEXIST)
        jail::panic("mkdir jail failed");

    if(jail_dir_path[jail_dir_path.size()-1] != '/')
        jail_dir_path += "/";
    
    // mount tmpfs in jail directory, so we don't write any files on disk
    SYSC(mount("none", jail_dir_path.c_str(), "tmpfs", 0, "mode=755"), "mount ympfs failed");
    
    SYSC(mount(jail_dir_path.c_str(), jail_dir_path.c_str(), NULL, MS_BIND, NULL), "mount bind jail_dir failed");
    
    for (mount_entry& ent: mounts) {
        std::string in_path = jail_dir_path + (ent.in_path[0] == '/' ? ent.in_path.substr(1) : ent.in_path);
        std::cout<<"bind mounting "<<ent.out_path<<" -> "<<in_path<<'\n';
        // create destination file (needed for bind mount)
        int tmp_fd = open(in_path.c_str(), O_CREAT, 0777);
        if(tmp_fd < 0) {
            printf("%m ");
            jail::panic("create mount file failed");
        }
        close(tmp_fd);

        SYSC(mount(ent.out_path.c_str(), in_path.c_str(), NULL, MS_BIND, NULL), "bind mount failed");
       
        // remount for flags to take effect
        int mount_flags = MS_BIND | MS_REMOUNT;
        if(ent.read_only)
            mount_flags |= MS_RDONLY;
        SYSC(mount(ent.out_path.c_str(), in_path.c_str(), NULL, mount_flags, NULL), "rebind mount failed");
    }

    SYSC(chdir(jail_dir_path.c_str()), "chdir jail_dir failed");
    // change root fs to jail directorty
    SYSC(syscall(SYS_pivot_root, ".", "."), "pivot_root failed");
    // unmount old root
    SYSC(umount2(".", MNT_DETACH), "umount failed");

    }

void Namespaces::addMountPath(const mount_entry& ent) {
    mounts.push_back(ent);
}

};
