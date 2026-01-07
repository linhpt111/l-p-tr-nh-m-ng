#include "utils.h"
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int copy_parent_dir(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) return -1;

    size_t len = strlen(path);
    if (len == 0) return -1;

    // Find last path separator
    ssize_t idx = (ssize_t)len - 1;
    for (; idx >= 0; idx--) {
        if (path[idx] == '/' || path[idx] == '\\') break;
    }
    if (idx <= 0) return -1;

    size_t copy_len = (size_t)idx;
    if (copy_len >= out_size) return -1;

    memcpy(out, path, copy_len);
    out[copy_len] = '\0';
    return 0;
}

static int get_executable_path(char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) return -1;
#ifdef _WIN32
    DWORD len = GetModuleFileNameA(NULL, buf, (DWORD)buf_size);
    if (len == 0 || len == buf_size) {
        LOG_ERROR("GetModuleFileNameA failed: %lu", GetLastError());
        return -1;
    }
#else
    ssize_t len = readlink("/proc/self/exe", buf, buf_size - 1);
    if (len == -1 || (size_t)len >= buf_size) {
        LOG_ERROR("readlink /proc/self/exe failed: %s", strerror(errno));
        return -1;
    }
    buf[len] = '\0';
#endif
    return 0;
}

int set_workdir_to_project_root(void) {
    char exe_path[PATH_MAX];
    char exe_dir[PATH_MAX];
    char root_dir[PATH_MAX];

    if (get_executable_path(exe_path, sizeof(exe_path)) != 0) {
        return -1;
    }
    if (copy_parent_dir(exe_path, exe_dir, sizeof(exe_dir)) != 0) {
        LOG_ERROR("Failed to get executable directory");
        return -1;
    }
    // Parent of /bin = project root
    if (copy_parent_dir(exe_dir, root_dir, sizeof(root_dir)) != 0) {
        LOG_ERROR("Failed to get project root directory");
        return -1;
    }

#ifdef _WIN32
    if (!SetCurrentDirectoryA(root_dir)) {
        LOG_ERROR("Failed to set working directory: %lu", GetLastError());
        return -1;
    }
#else
    if (chdir(root_dir) != 0) {
        LOG_ERROR("Failed to set working directory: %s", strerror(errno));
        return -1;
    }
#endif
    return 0;
}
