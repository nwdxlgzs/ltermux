# ltermux
Thread safe Lua Termux module (SVC)

# demo
```lua
local pty = require("ltermux")

-- 回调函数来处理子进程输出
local function handle_output( data)
    print(data)
end
-- 定义命令及参数
local cmd = "test"
local cwd = "/sdcard"
local args = {} -- 参数列表
local envVars = nil -- 使用默认环境
envVars = { -- 自定义环境
    "PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin",
    "HOME=/sdcard",
    "LD_LIBRARY_PATH="..tostring(activity.getFilesDir()),
}
local rows = 24
local columns = 80
local cell_width = 8
local cell_height = 16

-- 创建子进程，获取 ptm_fd, pid, cb_data
local ptm_fd, pid, cb_data = pty.create_subprocess(cmd, cwd, args, envVars, rows, columns, cell_width, cell_height, handle_output)
i=1
if not ptm_fd then
    print("Failed to create subprocess")
    os.exit(1)
else
    print("PTY FD:", ptm_fd, "PID:", pid)
    -- 调整窗口大小（可选）
    pty.set_pty_window_size(ptm_fd, 30, 100, 8, 16)
    -- 启用 UTF-8 模式
    pty.set_pty_utf8_mode(ptm_fd)
    while true do
        pty.process_messages(cb_data)
        -- 写入命令到子进程标准输入
        i=i+1
        if i<10 then
            pty.write_stdin(ptm_fd,i.. "\n")
        else
            pty.write_stdin(ptm_fd, "exit\n")
            -- 检查子进程是否结束
            local status = pty.wait_for(pid)
            if status then
                print("Subprocess exited with status:", status)
                break
            end
        end
        os.execute("sleep 0.1") -- 暂停 0.1 秒
    end

    -- 终止子进程并清理资源
    pty.terminate_subprocess(cb_data)

    -- 关闭 PTY 文件描述符
    pty.close(ptm_fd)
end
```

# test.c
```c
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        printf("Received: %s", buffer);
        if (strcmp(buffer, "exit\n") == 0) {
            printf("QUIT");
            break;
        }
        printf("WAIT");
    }
    return 0;
}
```
