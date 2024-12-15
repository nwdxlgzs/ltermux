#include "linux_syscall_support.h"
#include <lua.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>

typedef struct message_t {
    char *data;
    struct message_t *next;
} message_t;

typedef struct {
    message_t *head;
    message_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    uint8_t should_terminate;
} message_queue_t;
typedef struct {
    lua_State *L;
    int callback_ref;
    int ptm_fd;
    pthread_t thread;
    int pid;
    message_queue_t queue;
    int should_terminate;
} callback_data_t;

static void queue_init(message_queue_t *queue) {
    queue->head = queue->tail = NULL;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
}

static void queue_destroy(message_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    message_t *current = queue->head;
    while (current) {
        message_t *tmp = current;
        current = current->next;
        free(tmp->data);
        free(tmp);
    }
    pthread_mutex_unlock(&queue->mutex);
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->cond);
}

static void queue_push(message_queue_t *queue, const char *data) {
    message_t *msg = malloc(sizeof(message_t));
    if (!msg) return;
    msg->data = strdup(data);
    msg->next = NULL;

    pthread_mutex_lock(&queue->mutex);
    if (queue->tail) {
        queue->tail->next = msg;
        queue->tail = msg;
    } else {
        queue->head = queue->tail = msg;
    }
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
}

static void *pty_reader_thread(void *arg) {
    callback_data_t *cb_data = (callback_data_t *) arg;
    char buffer[4096];
    ssize_t bytes_read;

    while (1) {
        pthread_mutex_lock(&cb_data->queue.mutex);
        if (cb_data->should_terminate) {
            pthread_mutex_unlock(&cb_data->queue.mutex);
            break;
        }
        pthread_mutex_unlock(&cb_data->queue.mutex);

        bytes_read = read(cb_data->ptm_fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            queue_push(&cb_data->queue, buffer);
        } else if (bytes_read == 0) {
            break;
        } else {
            if (errno == EINTR)
                continue;
            else
                break;
        }
    }

    return NULL;
}

static int create_subprocess(lua_State *L) {
    // 参数:
    // 1. cmd (string)
    // 2. cwd (string)
    // 3. args (table)
    // 4. envVars (table)
    // 5. rows (number)
    // 6. columns (number)
    // 7. cell_width (number)
    // 8. cell_height (number)
    // 9. callback (function)

    const char *cmd = luaL_checkstring(L, 1);
    const char *cwd = luaL_checkstring(L, 2);

    // 获取 args 表
    int args_size = 0;
    char **argv = NULL;
    if (lua_istable(L, 3)) {
        args_size = luaL_len(L, 3);
        argv = malloc((args_size + 2) * sizeof(char *)); // +2 为 cmd 和 NULL
        if (!argv) return luaL_error(L, "Couldn't allocate argv array");
        argv[0] = strdup(cmd); // argv[0] 是命令本身
        for (int i = 0; i < args_size; ++i) {
            lua_rawgeti(L, 3, i + 1);
            if (!lua_isstring(L, -1)) {
                // 清理
                for (int j = 0; j <= i; ++j) free(argv[j]);
                free(argv);
                return luaL_error(L, "Arguments must be strings");
            }
            const char *arg = lua_tostring(L, -1);
            argv[i + 1] = strdup(arg);
            lua_pop(L, 1);
        }
        argv[args_size + 1] = NULL;
    }

    // 获取 envVars 表
    int env_size = 0;
    char **envp = NULL;
    if (lua_istable(L, 4)) {
        env_size = luaL_len(L, 4);
        envp = malloc((env_size + 1) * sizeof(char *));
        if (!envp) {
            if (argv) {
                for (int j = 0; j <= args_size; ++j) free(argv[j]);
                free(argv);
            }
            return luaL_error(L, "malloc() for envp array failed");
        }
        for (int i = 0; i < env_size; ++i) {
            lua_rawgeti(L, 4, i + 1);
            if (!lua_isstring(L, -1)) {
                // 清理
                for (int j = 0; j < i; ++j) free(envp[j]);
                free(envp);
                if (argv) {
                    for (int j = 0; j <= args_size; ++j) free(argv[j]);
                    free(argv);
                }
                return luaL_error(L, "Environment variables must be strings");
            }
            const char *env = lua_tostring(L, -1);
            envp[i] = strdup(env);
            lua_pop(L, 1);
        }
        envp[env_size] = NULL;
    }

    // 获取窗口大小参数
    unsigned short rows = luaL_checkinteger(L, 5);
    unsigned short columns = luaL_checkinteger(L, 6);
    unsigned short cell_width = luaL_checkinteger(L, 7);
    unsigned short cell_height = luaL_checkinteger(L, 8);

    // 获取回调函数
    if (!lua_isfunction(L, 9)) {
        if (envp) {
            for (int j = 0; j < env_size; ++j) free(envp[j]);
            free(envp);
        }
        if (argv) {
            for (int j = 0; j <= args_size; ++j) free(argv[j]);
            free(argv);
        }
        return luaL_error(L, "Callback must be a function");
    }
    // 在注册表中创建回调引用
    lua_pushvalue(L, 9);
    int callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // 创建 PTY 主端
    int ptm = sys_open("/dev/ptmx", O_RDWR | O_CLOEXEC, 0);
    if (ptm < 0) {
        if (envp) {
            for (int j = 0; j < env_size; ++j) free(envp[j]);
            free(envp);
        }
        if (argv) {
            for (int j = 0; j <= args_size; ++j) free(argv[j]);
            free(argv);
        }
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return luaL_error(L, "Cannot open /dev/ptmx");
    }

#ifndef LACKS_PTSNAME_R
    char devname[64];
    if (grantpt(ptm) || unlockpt(ptm) || ptsname_r(ptm, devname, sizeof(devname))) {
#else
        char* devname;
    if (grantpt(ptm) || unlockpt(ptm) || (devname = ptsname(ptm)) == NULL) {
#endif
        sys_close(ptm);
        if (envp) {
            for (int j = 0; j < env_size; ++j) free(envp[j]);
            free(envp);
        }
        if (argv) {
            for (int j = 0; j <= args_size; ++j) free(argv[j]);
            free(argv);
        }
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return luaL_error(L, "Cannot grantpt()/unlockpt()/ptsname_r() on /dev/ptmx");
    }

    // 设置 UTF-8 模式并禁用流控
    struct termios tios;
    if (tcgetattr(ptm, &tios) != 0) {
        sys_close(ptm);
        if (envp) {
            for (int j = 0; j < env_size; ++j) free(envp[j]);
            free(envp);
        }
        if (argv) {
            for (int j = 0; j <= args_size; ++j) free(argv[j]);
            free(argv);
        }
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return luaL_error(L, "tcgetattr() failed");
    }
    tios.c_iflag |= IUTF8;
    tios.c_iflag &= ~(IXON | IXOFF);
    if (tcsetattr(ptm, TCSANOW, &tios) != 0) {
        sys_close(ptm);
        if (envp) {
            for (int j = 0; j < env_size; ++j) free(envp[j]);
            free(envp);
        }
        if (argv) {
            for (int j = 0; j <= args_size; ++j) free(argv[j]);
            free(argv);
        }
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return luaL_error(L, "tcsetattr() failed");
    }

    // 设置初始窗口大小
    struct winsize sz = {
            .ws_row=rows,
            .ws_col=columns,
            .ws_xpixel=(columns * cell_width),
            .ws_ypixel=(rows * cell_height),
    };
    if (sys_ioctl(ptm, TIOCSWINSZ, &sz) != 0) {
        // 非致命错误，继续
    }

    pid_t pid = sys_fork();
    if (pid < 0) {
        sys_close(ptm);
        if (envp) {
            for (int j = 0; j < env_size; ++j) free(envp[j]);
            free(envp);
        }
        if (argv) {
            for (int j = 0; j <= args_size; ++j) free(argv[j]);
            free(argv);
        }
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return luaL_error(L, "Fork failed");
    } else if (pid > 0) {
        // 父进程
        // 初始化回调数据
        callback_data_t *cb_data = malloc(sizeof(callback_data_t));
        if (!cb_data) {
            sys_close(ptm);
            if (envp) {
                for (int j = 0; j < env_size; ++j) free(envp[j]);
                free(envp);
            }
            if (argv) {
                for (int j = 0; j <= args_size; ++j) free(argv[j]);
                free(argv);
            }
            luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
            return luaL_error(L, "Failed to allocate callback data");
        }
        cb_data->L = L;
        cb_data->callback_ref = callback_ref;
        cb_data->ptm_fd = ptm;
        cb_data->pid = pid;
        cb_data->should_terminate = 0;
        queue_init(&cb_data->queue);

        // 启动读取线程
        if (pthread_create(&cb_data->thread, NULL, pty_reader_thread, cb_data) != 0) {
            sys_close(ptm);
            queue_destroy(&cb_data->queue);
            free(cb_data);
            if (envp) {
                for (int j = 0; j < env_size; ++j) free(envp[j]);
                free(envp);
            }
            if (argv) {
                for (int j = 0; j <= args_size; ++j) free(argv[j]);
                free(argv);
            }
            luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
            return luaL_error(L, "Failed to create reader thread");
        }

        // 清理父进程中的内存
        if (envp) {
            for (int j = 0; j < env_size; ++j) free(envp[j]);
            free(envp);
        }
        if (argv) {
            for (int j = 0; j <= args_size; ++j) free(argv[j]);
            free(argv);
        }

        // 返回 ptm, pid, cb_data
        lua_pushinteger(L, ptm);
        lua_pushinteger(L, (lua_Integer) pid);
        lua_pushlightuserdata(L, cb_data); // 返回回调数据用于后续管理
        return 3; // 返回 ptm, pid, cb_data
    } else {
        // 子进程
        // 解除信号阻塞
        struct kernel_sigset_t signals_to_unblock;
        sys_sigfillset(&signals_to_unblock);
        sys_sigprocmask(SIG_UNBLOCK, &signals_to_unblock, NULL);

        // 关闭 PTM
        sys_close(ptm);

        // 创建新会话
        if (sys_setsid() < 0) sys__exit(1);

#ifndef LACKS_PTSNAME_R
        int pts = sys_open(devname, O_RDWR, 0);
#else
        int pts = sys_open(devname, O_RDWR,0);
#endif
        if (pts < 0) sys__exit(1);

        // 重定向标准文件描述符
        sys_dup2(pts, STDIN_FILENO);
        sys_dup2(pts, STDOUT_FILENO);
        sys_dup2(pts, STDERR_FILENO);
        if (pts > STDERR_FILENO) sys_close(pts);

        // 关闭其他文件描述符
        DIR *self_dir = opendir("/proc/self/fd");
        if (self_dir != NULL) {
            int self_dir_fd = dirfd(self_dir);
            struct dirent *entry;
            while ((entry = readdir(self_dir)) != NULL) {
                int fd = atoi(entry->d_name);
                if (fd > STDERR_FILENO && fd != self_dir_fd) sys_close(fd);
            }
            closedir(self_dir);
        }


        // 设置新的环境变量
        if (envp) {
            // 清除环境变量
            clearenv();
            for (int i = 0; envp[i]; ++i) {
                putenv(envp[i]);
            }
        }

        // 切换工作目录
        if (sys_chdir(cwd) != 0) {
            char *error_message;
            // No need to free asprintf()-allocated memory since doing execvp() or exit() below.
            if (asprintf(&error_message, "chdir(\"%s\")", cwd) == -1) error_message = "chdir()";
            perror(error_message);
            fflush(stderr);
            // 继续执行 exec
        }

        // 执行命令
        execvp(cmd, argv);
        // 如果 exec 失败
        char *error_message;
        if (asprintf(&error_message, "exec(\"%s\")", cmd) == -1) error_message = "exec()";
        perror(error_message);
        sys__exit(1);
        return 0;
    }
}

// Lua 模块函数：设置窗口大小
static int set_pty_window_size_lua(lua_State *L) {
    // 参数:
    // 1. fd (number)
    // 2. rows (number)
    // 3. cols (number)
    // 4. cell_width (number)
    // 5. cell_height (number)

    int fd = luaL_checkinteger(L, 1);
    int rows = luaL_checkinteger(L, 2);
    int cols = luaL_checkinteger(L, 3);
    int cell_width = luaL_checkinteger(L, 4);
    int cell_height = luaL_checkinteger(L, 5);

    struct winsize sz;
    memset(&sz, 0, sizeof(sz));
    sz.ws_row = (unsigned short) rows;
    sz.ws_col = (unsigned short) cols;
    sz.ws_xpixel = (unsigned short) (cols * cell_width);
    sz.ws_ypixel = (unsigned short) (rows * cell_height);
    if (sys_ioctl(fd, TIOCSWINSZ, &sz) != 0) {
        return luaL_error(L, "ioctl(TIOCSWINSZ) failed");
    }

    return 0; // 无返回值
}

// Lua 模块函数：设置 UTF-8 模式
static int set_pty_utf8_mode(lua_State *L) {
    // 参数:
    // 1. fd (number)
    int fd = luaL_checkinteger(L, 1);

    struct termios tios;
    if (tcgetattr(fd, &tios) != 0) {
        return luaL_error(L, "tcgetattr() failed");
    }
    if ((tios.c_iflag & IUTF8) == 0) {
        tios.c_iflag |= IUTF8;
        if (tcsetattr(fd, TCSANOW, &tios) != 0) {
            return luaL_error(L, "tcsetattr() failed");
        }
    }

    return 0;
}

// Lua 模块函数：等待子进程
static int wait_for_lua(lua_State *L) {
    // 参数:
    // 1. pid (number)
    int pid = luaL_checkinteger(L, 1);
    int status;
    if (sys_waitpid(pid, &status, 0) < 0) {
        return luaL_error(L, "waitpid() failed");
    }
    if (WIFEXITED(status)) {
        lua_pushinteger(L, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        lua_pushinteger(L, -WTERMSIG(status));
    } else {
        lua_pushinteger(L, 0);
    }
    return 1; // 返回退出状态
}

// Lua 模块函数：关闭文件描述符
static int close_fd_lua(lua_State *L) {
    // 参数:
    // 1. fd (number)
    int fd = luaL_checkinteger(L, 1);
    if (sys_close(fd) != 0) {
        return luaL_error(L, "close() failed");
    }
    return 0;
}

// Lua 模块函数：终止子进程并清理资源
static int terminate_subprocess(lua_State *L) {
    // 参数:
    // 1. cb_data (lightuserdata)
    callback_data_t *cb_data = lua_touserdata(L, 1);
    if (!cb_data) {
        return luaL_error(L, "Invalid callback data");
    }

    // 通知子线程终止
    pthread_mutex_lock(&cb_data->queue.mutex);
    cb_data->should_terminate = 1;
    pthread_cond_signal(&cb_data->queue.cond);
    pthread_mutex_unlock(&cb_data->queue.mutex);

    // 等待子线程结束
    pthread_join(cb_data->thread, NULL);

    // 处理队列中的剩余消息
    pthread_mutex_lock(&cb_data->queue.mutex);
    message_t *msg = cb_data->queue.head;
    while (msg) {
        // 获取回调函数
        lua_rawgeti(cb_data->L, LUA_REGISTRYINDEX, cb_data->callback_ref);
        lua_pushstring(cb_data->L, msg->data);
        if (lua_pcall(cb_data->L, 1, 0, 0) != LUA_OK) {
            fprintf(stderr, "Error in Lua callback: %s\n", lua_tostring(cb_data->L, -1));
            lua_pop(cb_data->L, 1); // 移除错误消息
        }
        message_t *tmp = msg;
        msg = msg->next;
        free(tmp->data);
        free(tmp);
    }
    cb_data->queue.head = cb_data->queue.tail = NULL;
    pthread_mutex_unlock(&cb_data->queue.mutex);

    // 销毁队列
    queue_destroy(&cb_data->queue);

    // 解除回调引用
    luaL_unref(cb_data->L, LUA_REGISTRYINDEX, cb_data->callback_ref);

    // 释放回调数据
    free(cb_data);

    return 0;
}

// Lua 模块函数：处理队列中的消息，并在主线程中调用回调
static int process_messages(lua_State *L) {
    // 参数:
    // 1. cb_data (lightuserdata)
    callback_data_t *cb_data = lua_touserdata(L, 1);
    if (!cb_data) {
        return luaL_error(L, "Invalid callback data");
    }

    // 锁定队列
    pthread_mutex_lock(&cb_data->queue.mutex);
    message_t *msg = cb_data->queue.head;
    while (msg) {
        // 解除队列中的消息
        cb_data->queue.head = msg->next;
        if (cb_data->queue.head == NULL) {
            cb_data->queue.tail = NULL;
        }
        pthread_mutex_unlock(&cb_data->queue.mutex);

        // 调用 Lua 回调
        lua_rawgeti(L, LUA_REGISTRYINDEX, cb_data->callback_ref);
        lua_pushstring(L, msg->data);
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            fprintf(stderr, "Error in Lua callback: %s\n", lua_tostring(L, -1));
            lua_pop(L, 1); // 移除错误消息
        }

        // 释放消息
        free(msg->data);
        free(msg);

        // 重新锁定队列
        pthread_mutex_lock(&cb_data->queue.mutex);
        msg = cb_data->queue.head;
    }
    pthread_mutex_unlock(&cb_data->queue.mutex);

    return 0; // 无返回值
}

static int write_stdin(lua_State *L) {
    int fd = luaL_checkinteger(L, 1);
    if (lua_isstring(L, 2)) {
        size_t len;
        const char *input = lua_tolstring(L, 2, &len);
        if (sys_write(fd, input, len) != len) {
            return luaL_error(L, "Failed to write to stdin");
        }
    } else {
        return luaL_error(L, "Invalid input: must be a string");
    }
    return 0;
}

// Lua 模块函数列表
static const struct luaL_Reg pty_module_funcs[] = {
        {"create_subprocess",    create_subprocess},
        {"set_pty_window_size",  set_pty_window_size_lua},
        {"set_pty_utf8_mode",    set_pty_utf8_mode},
        {"wait_for",             wait_for_lua},
        {"close",                close_fd_lua},
        {"terminate_subprocess", terminate_subprocess},
        {"process_messages",     process_messages},
        {"write_stdin",          write_stdin},
        {NULL, NULL}
};


__attribute__((used))
int luaopen_ltermux(lua_State *L) {
    luaL_newlib(L, pty_module_funcs);
    return 1;
}
