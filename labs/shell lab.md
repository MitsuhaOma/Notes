## shell lab

### 我们需要填补的函数：

```C
void eval(char* cmdline); 
int builtin_cmd(char** argv);
void do_bgfg(char** argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
```

### Hints

> 参考 [shlab](http://csapp.cs.cmu.edu/3e/shlab.pdf) 以及csapp第八章

- 和书上列举的不同，`shlab`要求中一个进程组中只会有一个进程，所以我们只需要在子进程中使用`setpgid(0, 0)`设置进程组id与子进程pid值相同

- 当我们使用内置命令`bg`和`fg`的时候，我们需要考虑读取`pid`和`jid`。文档规定数字前带有`%`就是表示JID， 就单纯的数字就是代表PID，我们在实现程序的时候需要考虑对这个`id`的读取。

- 善用`make rtest01` ~ `make rtest15` ，这是标准答案的输出，确保你的测试结果和标准答案的输出完全相同

- waitpid中的选项推荐使用`WUNTRACED`和`WNOHANG`

> 对书上模式的解释，我们可以很明显的知道，当父进程收到一个SIGCHLD时，会触发sigchld_handler中的内容，这个函数也是唯一使用waitpid的程序。而SIGCHLD是通知父进程其子进程停止或者终止, 而此时至少有一个子进程停止或终止，所以在while中必定能有一个pid>0,  可以有效地回收每一个后台进程，而不用挂起父进程，一直等待所有进程结束。

- 在waitfg中使用sleep陷入循环，直到前台进程运行结束，我们可以通过`fgpid(jobs) != 0`来判断前台进程运行是否结束
- `sigint_handler` 和 `sigtstp_handler` 传递相应的信号给前台进程组，如果前台进程组不存在，就不传

### Let’s begin our shell lab

> 我们只罗列要填补并且在当前步骤要改动的函数

#### First: 根据书本已有的部分参考代码填写函数

```c
// 参考书本p525 code/ecf/shellex.c
void eval(char* cmdline) {
    char* argv[MAXARGS];
    char buf[MAXLINE];
    int bg;
    pid_t pid;

    strcpy(buf, cmdline);
    bg = parseline(buf, argv);
    if (argv[0] == NULL) {
        return;
    }
    if (!builtin_cmd(argv)) {
        if ((pid = fork()) == 0) {
            if (execve(argv[0], argv, environ) < 0) {
                printf("%s: Command not found.\n", argv[0]);
                exit(0);
            }
        }

        if (!bg) {
            int status;
            if (waitpid(pid, &status, 0) < 0) {
                unix_error("waitfg: waitpid error");
            }
        } else {
            printf("%d %s", pid, cmdline);
        }
    }

    return;
}

int builtin_cmd(char** argv) {
    if (!strcmp(argv[0], "quit")) {
        exit(0);
    }
    if (!strcmp(argv[0], "&")) {
        return 1;
    }
    return 0; /* not a builtin command */
}
```

```c
// 参考书本p543 code/ecf/procmask2.c
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    pid_t pid;

    sigfillset(&mask_all);
    while ((pid = waitpid(-1, NULL, 0)) > 0) {
        sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        deletejob(jobs, pid);
        sigprocmask(SIG_SETMASK, &prev_all, NULL);
    }

    if (errno != ECHILD) {
        unix_error("waitpid error");
    }
    errno = olderrno;
}

void eval(char* cmdline) {
    char* argv[MAXARGS];
    char buf[MAXLINE];
    int bg;
    pid_t pid;
    sigset_t mask_all, mask_one, prev_one;

    sigfillset(&mask_all);
    sigemptyset(&mask_one);
    sigaddset(&mask_one, SIGCHLD);

    strcpy(buf, cmdline);
    bg = parseline(buf, argv);
    if (argv[0] == NULL) {
        return;
    }
    if (!builtin_cmd(argv)) {
        sigprocmask(SIG_BLOCK, &mask_one, &prev_one);
        if ((pid = fork()) == 0) {
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            if (execve(argv[0], argv, environ) < 0) {
                printf("%s: Command not found.\n", argv[0]);
                exit(0);
            }
        }

        if (!bg) {
            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            addjob(jobs, pid, FG, cmdline);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);

            int status;
            if (waitpid(pid, &status, 0) < 0) {
                unix_error("waitfg: waitpid error");
            }
        } else {
            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            addjob(jobs, pid, BG, cmdline);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);

            printf("%d %s", pid, cmdline);
        }
    }

    return;
}
```

```c
//参考书本p543 code/ecf/sigsuspend.c
void eval(char* cmdline) {
    if (!builtin_cmd(argv)) {
       /* ... */
        if (!bg) {
            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            addjob(jobs, pid, FG, cmdline);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);

            waitfg(pid);
            
            int status;
            if (waitpid(pid, &status, 0) < 0) {
                unix_error("waitfg: waitpid error");
            }
        }
    	/* ... */
    }

    return;
}

void waitfg(pid_t pid) {
    sigset_t mask;
    sigemptyset(&mask);

    while (fgpid(jobs) > 0) {
        sigsuspend(&mask);
    }
}
```

#### Second：根据提示信息填写函数并进一步完善函数

- 我们可以从书中，shell使用作业的概念来表示对一条命令行求值而创建的进程（p529），shell为每一个作业创建一个独立的进程组。**所以所有的子进程，都应该升级成一个进程组**
- 同时，把`waitpid`的操作回收，由`sigchld_handler`负责

```c
void eval(char* cmdline) {
    /* ... */
    if (!builtin_cmd(argv)) {
        sigprocmask(SIG_BLOCK, &mask_one, &prev_one);
        if ((pid = fork()) == 0) {
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            
            setpgid(0, 0)
                 
            if (execve(argv[0], argv, environ) < 0) {
                printf("%s: Command not found.\n", argv[0]);
                exit(0);
            }
        }
        
        if (!bg) {
            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            addjob(jobs, pid, FG, cmdline);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);

            waitfg(pid);
        }

        /* ... */
    }

    return;
}
```

-  父进程在接收到sigint和sigstp信号时，会向前台进程组发送对应的信号，所以sigint_handler和sigstp_handler起到的是一个**当前台进程组存在的时候**就向发送对应信号的作用

```C
void sigint_handler(int sig) {
    int olderrno = errno;
    pid_t pid;

    if ((pid = fgpid(jobs)) > 0) {
        kill(-pid, SIGINT);
    }

    errno = olderrno;
}

void sigtstp_handler(int sig) {
    int olderrno = errno;
    pid_t pid;

    if ((pid = fgpid(jobs)) > 0) {
        kill(-pid, SIGTSTP);
    }

    errno = olderrno;
}
```

- 查看 [shlab](http://csapp.cs.cmu.edu/3e/shlab.pdf) 文档第二页，我们知道支持的内置命令有 `quit`,`jobs`,`bg`,`fg`

```c
int builtin_cmd(char** argv) {
    if (!strcmp(argv[0], "quit")) {
        exit(0);
    }
    if (!strcmp(argv[0], "jobs")) {
        listjobs(jobs);
        return 1;
    }
    if (!strcmp(argv[0], "bg") || !strcmp(argv[0], "fg")) {
        do_bgfg(argv);
        return 1;
    }
    if (!strcmp(argv[0], "&")) {
        return 1;
    }
    return 0; /* not a builtin command */
}
```

### Third:对比标准答案的输出，看看输出的格式，以及完善代码。

> 此时，我们已经完成了sigtstp_handler,  sigint_handler, waitfg, buildtin_cmd的编写

- 让我们依次使用`make rtest[no]`命令，当我们按顺序输入到`make rtest04`时

![image-20211128121758415](C:\Users\Lenovo\AppData\Roaming\Typora\typora-user-images\image-20211128121758415.png)

我们可以看到 终端会打印后台运行的信息，我们根据此，对于`eval`函数进行一个修改

```c
void eval(char* cmdline) {
    /* ... */
    if (!builtin_cmd(argv)) {
        /* ... */

        if (!bg) {
            /* ... */
        } else {
            struct job_t* job;

            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            addjob(jobs, pid, BG, cmdline);
            job = getjobpid(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);

            printf("[%d] (%d) %s", job->jid, pid, cmdline);
        }
    }

    return;
}
```

终端输入`make rtest06`时，我们可以看到，

![image-20211128122804139](C:\Users\Lenovo\AppData\Roaming\Typora\typora-user-images\image-20211128122804139.png)

这里，我们需要理清一个小逻辑，就是当我们的子进程终止或停止的时候，会向父进程发送一个`sigchld`的信号，所以我们要在`sigchld_handler`函数中去处理这个信息，我们可以看到，返回的信息，包括了子进程是被终止还是被停止，被哪个信号终止，还有相应的pid和jid。因此，我们需要对`sigchld_handler`进行一个修改

同时，errno值为ECHILD的前提是回收了所有的子进程，并且再次调用了waitpid, 而我们对于sigchld的定位为，有就回收，每次调用会至少回收一个（因为触发这个函数就需要有至少一个子进程终止或停止），所以要删除书上这里对errno判断的代码。

```c
// 这里还参考了p520 code/ecf/waitpid2.c
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    pid_t pid;
    int status;

    sigfillset(&mask_all);
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        struct job_t* job = getjobpid(jobs, pid);
        if (WIFSTOPPED(status)) {
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            printf("Job [%d] (%d) stopped by signal %d", job->jid, job->pid, WSTOPSIG(status));
            job->state = ST;
            sigprocmask(SIG_SETMASK, &prev_all, NULL);
        }
        if (WIFSIGNALED(status)) {
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            printf("Job [%d] (%d) terminated by signal %d", job->jid, job->pid, WSTOPSIG(status));
            deletejob(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_all, NULL);
        }
        if (WIFEXITED(status)) {
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            deletejob(jobs, pid);
            sigprocmask(SIG_SETMASK, &prev_all, NULL);
        }
    }
    
    errno = olderrno;
}
```

我们测试到`make rtest09`的时候，我们发现使用bg命令时有额外的输出，同时呢，我们也通过`./tshref`看一下bg命令还有什么输出格式上的区别

![img](file:///D:\qq\messageRecords\2391542095\Image\C2C\IA~JU[`1@@]~W6LLM0EGD8U.png)

![image-20211128212927620](C:\Users\Lenovo\AppData\Roaming\Typora\typora-user-images\image-20211128212927620.png)

```c
void do_bgfg(char** argv) {
    // argv数组的结束部分是NULL，这里说明命令只有bg, fg, 而缺少了必要的参数jid或pid
    if (argv[1] == NULL) {
        printf("%s command requires PID or %%jobid argument\n", argv[1]);
        return;
    }
    int id;
    struct job_t* job;

    // sscanf如果匹配成功会返回匹配成功的数目，如果匹配失败则返回0
    if (sscanf(argv[1], "%%%d", &id) > 0) {
        job = getjobjid(jobs, id);
        if (job == NULL) {
            printf("%%%d: No such process\n", id);
            return;
        }
    } else if (sscanf(argv[1], "%d", &id) > 0) {
        job = getjobpid(jobs, id);
        if (job == NULL) {
            printf("(%d): No such process\n", id);
            return;
        }
    } else {
        printf("%s: argument must be a PID or %%jobid\n", argv[0]);
        return;
    }

    sigset_t mask_all, prev_all;
    sigfillset(&mask_all);

    if (!strcmp(argv[1], "bg")) {
        sigprocmask(SIG_BLOCK, &mask_all, NULL);
        kill(-job->pid, SIGCONT);
        job->state = BG;
        printf("[%d] (%d) %s", job->jid, job->pid, job->cmdline);
        sigprocmask(SIG_SETMASK, &prev_all, NULL);
    }
    if (!strcmp(argv[1], "fg")) {
        sigprocmask(SIG_BLOCK, &mask_all, NULL);
        kill(-job->pid, SIGCONT);
        job->state = FG;
        sigprocmask(SIG_SETMASK, &prev_all, NULL);
        waitfg(job->pid);
    }
}
```

至此，我们就完成了7个函数的编写啦。

### 感想：

- 看书上一直理解不了`sigsuspend`，当时忽视了`pause`，没有注意书本对`sigsuspend`的描述为原子性的`pause`操作，而`pause`的操作呢，是挂起进程，直到收到一个信号。所以其实当我们在运行`waitfg`的时候，它会检测是否存在前台作业，当前台作业未完成时，它会挂起父进程，但是又不阻塞父进程接受其信号，从而允许父进程的后台作业完成并回收。
- 执行过程中的所有信号：
  - 首先，我们在键盘中使用的`ctrl+z`和`ctrl+c`是由终端向当前运行的进程，也就是`./tsh`发送了`SIGTSTP`和`SIGINT`信号，父进程中，我们编写`sigtstp_handler`与`sigint_handler`来确定父进程接收到这两个信号刚如何运行，根据要求，我们在两个函数中，实际上是这样一个逻辑：**如果存在前台进程组，就向前台进程组使用kill函数发送对应的信号**
  - 还有在使用`bg`和`fg`这两个命令时，我们需要通过使用kill函数向对应的作业（进程组）发送一个`sigcont`信号。
  - `sigchld`：这个信号对应的事件是父进程的一个子进程停止或者终止。























