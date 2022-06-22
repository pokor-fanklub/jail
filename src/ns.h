#pragma once

#include <string>
#include <vector>

namespace jail {
    
class Namespaces {
    public:
        Namespaces() {};
        void isolate();

        struct mount_entry {
            std::string out_path;
            std::string in_path;
            bool read_only;
        };

        void addMountPath(const mount_entry& entry);

    private:
        void createPath(std::string path);

        std::string jail_dir_path = "./jail_mp";
        std::vector<mount_entry> mounts;
        
};

}
