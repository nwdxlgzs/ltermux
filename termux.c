#include "linux_syscall_support.h"
#include <lua.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <dirent.h>
#include <stdlib.h>
#include <termios.h>
#include <pthread.h>

#define BUFFSZ_ON_STACK 4096
typedef struct message_t {
    char *data;
    int datalen;
    int databuffsz;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    uint8_t should_terminate;
    char BUFF[BUFFSZ_ON_STACK];
} message_t;
typedef struct {
    lua_State *L;
    int callback_ref;
    int ptm_fd;
    pthread_t thread;
    int pid;
    message_t message;
    int should_terminate;
} callback_data_t;

static void msg_init(message_t *message) {
    message->datalen = 0;
    message->databuffsz = BUFFSZ_ON_STACK;
    memset(message->BUFF, BUFFSZ_ON_STACK, 0);
    message->data = message->BUFF;
    pthread_mutex_init(&message->mutex, NULL);
    pthread_cond_init(&message->cond, NULL);
}

static void msg_destroy(message_t *message) {
    pthread_mutex_lock(&message->mutex);
    if (message->data && message->data != message->BUFF) {
        free(message->data);
    }
    pthread_mutex_unlock(&message->mutex);
    pthread_mutex_destroy(&message->mutex);
    pthread_cond_destroy(&message->cond);
}

static void msg_push(message_t *message, const char *data) {
    int datastrlen = strlen(data);
    pthread_mutex_lock(&message->mutex);
    if (message->data == message->BUFF) {
        if (message->datalen + datastrlen >= BUFFSZ_ON_STACK) {
            message->databuffsz = message->datalen + datastrlen + BUFFSZ_ON_STACK;
            message->data = malloc(message->databuffsz);
            memset(message->data, message->databuffsz, 0);
            memcpy(message->data, message->BUFF, message->datalen);
        }
    } else {
        message->databuffsz = message->datalen + datastrlen + BUFFSZ_ON_STACK;
        message->data = realloc(message->data, message->databuffsz);
    }
    strcat(message->data, data);
    pthread_cond_signal(&message->cond);
    pthread_mutex_unlock(&message->mutex);
}

static void msg_pop_inlock(message_t *message) {
    if (message->data == message->BUFF) {
        message->data[0] = 0;
    } else if (message->data)free(message->data);
    message->data = message->BUFF;
    message->datalen = 0;
}

static void *pty_reader_thread(void *arg) {
    callback_data_t *cb_data = (callback_data_t *) arg;
    char buffer[4096];
    ssize_t bytes_read;

    while (1) {
        pthread_mutex_lock(&cb_data->message.mutex);
        if (cb_data->should_terminate) {
            pthread_mutex_unlock(&cb_data->message.mutex);
            break;
        }
        pthread_mutex_unlock(&cb_data->message.mutex);

        bytes_read = sys_read(cb_data->ptm_fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            msg_push(&cb_data->message, buffer);
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
        msg_init(&cb_data->message);

        // 启动读取线程
        if (pthread_create(&cb_data->thread, NULL, pty_reader_thread, cb_data) != 0) {
            sys_close(ptm);
            msg_destroy(&cb_data->message);
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
    pthread_mutex_lock(&cb_data->message.mutex);
    cb_data->should_terminate = 1;
    pthread_cond_signal(&cb_data->message.cond);
    pthread_mutex_unlock(&cb_data->message.mutex);

    // 等待子线程结束
    pthread_join(cb_data->thread, NULL);

    // 处理队列中的剩余消息
    pthread_mutex_lock(&cb_data->message.mutex);
    lua_rawgeti(cb_data->L, LUA_REGISTRYINDEX, cb_data->callback_ref);
    lua_pushstring(cb_data->L, cb_data->message.data);
    if (lua_pcall(cb_data->L, 1, 0, 0) != LUA_OK) {
        return luaL_error(L,"Error in Lua callback: %s\n", lua_tostring(L, -1));
    }
    pthread_mutex_unlock(&cb_data->message.mutex);

    // 销毁队列
    msg_destroy(&cb_data->message);

    // 解除回调引用
    luaL_unref(cb_data->L, LUA_REGISTRYINDEX, cb_data->callback_ref);

    // 释放回调数据
    free(cb_data);
    return 0;
}

static int process_messages(lua_State *L) {
    // 参数:
    // 1. cb_data (lightuserdata)
    callback_data_t *cb_data = lua_touserdata(L, 1);
    if (!cb_data) {
        return luaL_error(L, "Invalid callback data");
    }
    pthread_mutex_lock(&cb_data->message.mutex);
    char *buff = malloc(cb_data->message.datalen + 1);
    buff[cb_data->message.datalen] = 0;
    memcpy(buff, cb_data->message.data, cb_data->message.datalen);
    msg_pop_inlock(&cb_data->message);
    pthread_mutex_unlock(&cb_data->message.mutex);
    //这里不在锁内执行，方便那边上锁，我这里用副本就好
    lua_rawgeti(L, LUA_REGISTRYINDEX, cb_data->callback_ref);
    lua_pushstring(L, buff);
    if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
        return luaL_error(L,"Error in Lua callback: %s\n", lua_tostring(L, -1));
    }
    // 释放缓冲区
    free(buff);
    return 0;
}

static int write_stdin(lua_State *L) {
    int fd = luaL_checkinteger(L, 1);
    size_t len;
    const char *input = luaL_checklstring(L, 2, &len);
    if (sys_write(fd, input, len) != len) {
        return luaL_error(L, "Failed to write to stdin");
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
