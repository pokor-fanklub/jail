#include "ns.h"
#include "log.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>

#define SYSC(sys, msg) if(((sys))) {panic((msg), true);}

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
    // mounting 755 with root, process can't create new files
    SYSC(mount("none", jail_dir_path.c_str(), "tmpfs", 0, "mode=755"), "mount tmpfs failed");
    
    SYSC(mount(jail_dir_path.c_str(), jail_dir_path.c_str(), NULL, MS_BIND, NULL), "mount bind jail_dir failed");
    
    for (mount_entry& ent: mounts) {
        std::string in_path = jail_dir_path + (ent.in_path[0] == '/' ? ent.in_path.substr(1) : ent.in_path);
        std::cout<<"bind mounting "<<ent.out_path<<" -> "<<in_path<<'\n';
        // create destination file (needed for bind mount)

        // we can create files with no permissions, because only mounted file permissions matter
        createPath(in_path);
        int tmp_fd = open(in_path.c_str(), O_CREAT, 0000);
        if(tmp_fd < 0) {
            jail::panic("create mount file failed", true);
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

void Namespaces::createPath(std::string path) {
    if(!path.size())
        return;
    
    int last_slash = (path[0] == '/' ? 0 : -1);
    int pos = 0;
    int dir_depth = 0;
    while((pos = path.find('/', last_slash+1)) != -1) {
        std::string dir_path = path.substr(0, pos);
        std::string cur_dir = path.substr(last_slash+1, (pos-last_slash-1));
        if(cur_dir == "..") {
            if(--dir_depth < 0)
                jail::panic("path points outside jail");
        }
        int rc = mkdir(dir_path.c_str(), 0755);
        if(rc < 0 && errno != EEXIST) {
            jail::panic("mkdir on path failed", true);
        }
        last_slash = pos;
    }
    if(path.substr(last_slash+1) == ".." && !dir_depth)
        jail::panic("path points outside jail");
}

void Namespaces::addMountPath(const mount_entry& ent) {
    mounts.push_back(ent);
}

};
