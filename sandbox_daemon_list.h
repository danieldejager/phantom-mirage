/*
 * --sandbox-daemon allowlist (#16), included by sandbox_daemon.c.
 * Built from strace -f of the CI suites (smoke, subsystem echo, shell
 * and Python 3 services, status page, honeydctl, SIGHUP/SIGUSR1,
 * --sandbox-scripts, regress/ incl. nmap.py) on an ASan build, plus
 * the usual sh/Perl/Python 3 runtime calls, because exec'd scripts
 * and subsystems inherit the filter. Never add the deny-list calls
 * from sandbox.c (ptrace, mount, unshare, bpf, keyctl, ...).
 */
#ifdef __NR_accept
A(accept)
#endif
#ifdef __NR_accept4
A(accept4)
#endif
#ifdef __NR_access
A(access)
#endif
#ifdef __NR_alarm
A(alarm)
#endif
#ifdef __NR_arch_prctl
A(arch_prctl)
#endif
#ifdef __NR_bind
A(bind)
#endif
#ifdef __NR_brk
A(brk)
#endif
#ifdef __NR_capget
A(capget)
#endif
#ifdef __NR_capset
A(capset)
#endif
#ifdef __NR_chdir
A(chdir)
#endif
#ifdef __NR_chmod
A(chmod)
#endif
#ifdef __NR_chown
A(chown)
#endif
#ifdef __NR_clock_getres
A(clock_getres)
#endif
#ifdef __NR_clock_gettime
A(clock_gettime)
#endif
#ifdef __NR_clock_nanosleep
A(clock_nanosleep)
#endif
#ifdef __NR_clone
A(clone)
#endif
#ifdef __NR_clone3
A(clone3)
#endif
#ifdef __NR_close
A(close)
#endif
#ifdef __NR_close_range
A(close_range)
#endif
#ifdef __NR_connect
A(connect)
#endif
#ifdef __NR_copy_file_range
A(copy_file_range)
#endif
#ifdef __NR_dup
A(dup)
#endif
#ifdef __NR_dup2
A(dup2)
#endif
#ifdef __NR_dup3
A(dup3)
#endif
#ifdef __NR_epoll_create
A(epoll_create)
#endif
#ifdef __NR_epoll_create1
A(epoll_create1)
#endif
#ifdef __NR_epoll_ctl
A(epoll_ctl)
#endif
#ifdef __NR_epoll_pwait
A(epoll_pwait)
#endif
#ifdef __NR_epoll_pwait2
A(epoll_pwait2)
#endif
#ifdef __NR_epoll_wait
A(epoll_wait)
#endif
#ifdef __NR_eventfd
A(eventfd)
#endif
#ifdef __NR_eventfd2
A(eventfd2)
#endif
#ifdef __NR_execve
A(execve)
#endif
#ifdef __NR_exit
A(exit)
#endif
#ifdef __NR_exit_group
A(exit_group)
#endif
#ifdef __NR_faccessat
A(faccessat)
#endif
#ifdef __NR_faccessat2
A(faccessat2)
#endif
#ifdef __NR_fadvise64
A(fadvise64)
#endif
#ifdef __NR_fchdir
A(fchdir)
#endif
#ifdef __NR_fchmod
A(fchmod)
#endif
#ifdef __NR_fchmodat
A(fchmodat)
#endif
#ifdef __NR_fchown
A(fchown)
#endif
#ifdef __NR_fchownat
A(fchownat)
#endif
#ifdef __NR_fcntl
A(fcntl)
#endif
#ifdef __NR_fdatasync
A(fdatasync)
#endif
#ifdef __NR_fgetxattr
A(fgetxattr)
#endif
#ifdef __NR_flistxattr
A(flistxattr)
#endif
#ifdef __NR_flock
A(flock)
#endif
#ifdef __NR_fork
A(fork)
#endif
#ifdef __NR_fstat
A(fstat)
#endif
#ifdef __NR_fstatfs
A(fstatfs)
#endif
#ifdef __NR_fsync
A(fsync)
#endif
#ifdef __NR_ftruncate
A(ftruncate)
#endif
#ifdef __NR_futex
A(futex)
#endif
#ifdef __NR_futimesat
A(futimesat)
#endif
#ifdef __NR_get_robust_list
A(get_robust_list)
#endif
#ifdef __NR_getcpu
A(getcpu)
#endif
#ifdef __NR_getcwd
A(getcwd)
#endif
#ifdef __NR_getdents
A(getdents)
#endif
#ifdef __NR_getdents64
A(getdents64)
#endif
#ifdef __NR_getegid
A(getegid)
#endif
#ifdef __NR_geteuid
A(geteuid)
#endif
#ifdef __NR_getgid
A(getgid)
#endif
#ifdef __NR_getitimer
A(getitimer)
#endif
#ifdef __NR_getpeername
A(getpeername)
#endif
#ifdef __NR_getpgid
A(getpgid)
#endif
#ifdef __NR_getpgrp
A(getpgrp)
#endif
#ifdef __NR_getpid
A(getpid)
#endif
#ifdef __NR_getppid
A(getppid)
#endif
#ifdef __NR_getpriority
A(getpriority)
#endif
#ifdef __NR_getrandom
A(getrandom)
#endif
#ifdef __NR_getresgid
A(getresgid)
#endif
#ifdef __NR_getresuid
A(getresuid)
#endif
#ifdef __NR_getrlimit
A(getrlimit)
#endif
#ifdef __NR_getrusage
A(getrusage)
#endif
#ifdef __NR_getsid
A(getsid)
#endif
#ifdef __NR_getsockname
A(getsockname)
#endif
#ifdef __NR_getsockopt
A(getsockopt)
#endif
#ifdef __NR_gettid
A(gettid)
#endif
#ifdef __NR_gettimeofday
A(gettimeofday)
#endif
#ifdef __NR_getuid
A(getuid)
#endif
#ifdef __NR_getxattr
A(getxattr)
#endif
#ifdef __NR_ioctl
A(ioctl)
#endif
#ifdef __NR_kill
A(kill)
#endif
#ifdef __NR_landlock_add_rule
A(landlock_add_rule)
#endif
#ifdef __NR_landlock_create_ruleset
A(landlock_create_ruleset)
#endif
#ifdef __NR_landlock_restrict_self
A(landlock_restrict_self)
#endif
#ifdef __NR_lgetxattr
A(lgetxattr)
#endif
#ifdef __NR_link
A(link)
#endif
#ifdef __NR_linkat
A(linkat)
#endif
#ifdef __NR_listen
A(listen)
#endif
#ifdef __NR_listxattr
A(listxattr)
#endif
#ifdef __NR_llistxattr
A(llistxattr)
#endif
#ifdef __NR_lseek
A(lseek)
#endif
#ifdef __NR_lstat
A(lstat)
#endif
#ifdef __NR_madvise
A(madvise)
#endif
#ifdef __NR_membarrier
A(membarrier)
#endif
#ifdef __NR_memfd_create
A(memfd_create)
#endif
#ifdef __NR_mincore
A(mincore)
#endif
#ifdef __NR_mkdir
A(mkdir)
#endif
#ifdef __NR_mkdirat
A(mkdirat)
#endif
#ifdef __NR_mlock
A(mlock)
#endif
#ifdef __NR_mlockall
A(mlockall)
#endif
#ifdef __NR_mmap
A(mmap)
#endif
#ifdef __NR_mprotect
A(mprotect)
#endif
#ifdef __NR_mremap
A(mremap)
#endif
#ifdef __NR_msync
A(msync)
#endif
#ifdef __NR_munlock
A(munlock)
#endif
#ifdef __NR_munlockall
A(munlockall)
#endif
#ifdef __NR_munmap
A(munmap)
#endif
#ifdef __NR_nanosleep
A(nanosleep)
#endif
#ifdef __NR_newfstatat
A(newfstatat)
#endif
#ifdef __NR_open
A(open)
#endif
#ifdef __NR_openat
A(openat)
#endif
#ifdef __NR_pause
A(pause)
#endif
#ifdef __NR_pidfd_open
A(pidfd_open)
#endif
#ifdef __NR_pidfd_send_signal
A(pidfd_send_signal)
#endif
#ifdef __NR_pipe
A(pipe)
#endif
#ifdef __NR_pipe2
A(pipe2)
#endif
#ifdef __NR_poll
A(poll)
#endif
#ifdef __NR_ppoll
A(ppoll)
#endif
#ifdef __NR_prctl
A(prctl)
#endif
#ifdef __NR_pread64
A(pread64)
#endif
#ifdef __NR_preadv
A(preadv)
#endif
#ifdef __NR_prlimit64
A(prlimit64)
#endif
#ifdef __NR_pselect6
A(pselect6)
#endif
#ifdef __NR_pwrite64
A(pwrite64)
#endif
#ifdef __NR_pwritev
A(pwritev)
#endif
#ifdef __NR_read
A(read)
#endif
#ifdef __NR_readlink
A(readlink)
#endif
#ifdef __NR_readlinkat
A(readlinkat)
#endif
#ifdef __NR_readv
A(readv)
#endif
#ifdef __NR_recvfrom
A(recvfrom)
#endif
#ifdef __NR_recvmmsg
A(recvmmsg)
#endif
#ifdef __NR_recvmsg
A(recvmsg)
#endif
#ifdef __NR_rename
A(rename)
#endif
#ifdef __NR_renameat
A(renameat)
#endif
#ifdef __NR_renameat2
A(renameat2)
#endif
#ifdef __NR_restart_syscall
A(restart_syscall)
#endif
#ifdef __NR_rmdir
A(rmdir)
#endif
#ifdef __NR_rseq
A(rseq)
#endif
#ifdef __NR_rt_sigaction
A(rt_sigaction)
#endif
#ifdef __NR_rt_sigpending
A(rt_sigpending)
#endif
#ifdef __NR_rt_sigprocmask
A(rt_sigprocmask)
#endif
#ifdef __NR_rt_sigqueueinfo
A(rt_sigqueueinfo)
#endif
#ifdef __NR_rt_sigreturn
A(rt_sigreturn)
#endif
#ifdef __NR_rt_sigsuspend
A(rt_sigsuspend)
#endif
#ifdef __NR_rt_sigtimedwait
A(rt_sigtimedwait)
#endif
#ifdef __NR_sched_getaffinity
A(sched_getaffinity)
#endif
#ifdef __NR_sched_getparam
A(sched_getparam)
#endif
#ifdef __NR_sched_getscheduler
A(sched_getscheduler)
#endif
#ifdef __NR_sched_setaffinity
A(sched_setaffinity)
#endif
#ifdef __NR_sched_yield
A(sched_yield)
#endif
#ifdef __NR_seccomp
A(seccomp)
#endif
#ifdef __NR_select
A(select)
#endif
#ifdef __NR_sendfile
A(sendfile)
#endif
#ifdef __NR_sendmmsg
A(sendmmsg)
#endif
#ifdef __NR_sendmsg
A(sendmsg)
#endif
#ifdef __NR_sendto
A(sendto)
#endif
#ifdef __NR_set_robust_list
A(set_robust_list)
#endif
#ifdef __NR_set_tid_address
A(set_tid_address)
#endif
#ifdef __NR_setgid
A(setgid)
#endif
#ifdef __NR_setgroups
A(setgroups)
#endif
#ifdef __NR_setitimer
A(setitimer)
#endif
#ifdef __NR_setpgid
A(setpgid)
#endif
#ifdef __NR_setpriority
A(setpriority)
#endif
#ifdef __NR_setresgid
A(setresgid)
#endif
#ifdef __NR_setresuid
A(setresuid)
#endif
#ifdef __NR_setrlimit
A(setrlimit)
#endif
#ifdef __NR_setsid
A(setsid)
#endif
#ifdef __NR_setsockopt
A(setsockopt)
#endif
#ifdef __NR_setuid
A(setuid)
#endif
#ifdef __NR_shutdown
A(shutdown)
#endif
#ifdef __NR_sigaltstack
A(sigaltstack)
#endif
#ifdef __NR_socket
A(socket)
#endif
#ifdef __NR_socketpair
A(socketpair)
#endif
#ifdef __NR_splice
A(splice)
#endif
#ifdef __NR_stat
A(stat)
#endif
#ifdef __NR_statfs
A(statfs)
#endif
#ifdef __NR_statx
A(statx)
#endif
#ifdef __NR_symlink
A(symlink)
#endif
#ifdef __NR_symlinkat
A(symlinkat)
#endif
#ifdef __NR_sysinfo
A(sysinfo)
#endif
#ifdef __NR_tee
A(tee)
#endif
#ifdef __NR_tgkill
A(tgkill)
#endif
#ifdef __NR_time
A(time)
#endif
#ifdef __NR_timerfd_create
A(timerfd_create)
#endif
#ifdef __NR_timerfd_gettime
A(timerfd_gettime)
#endif
#ifdef __NR_timerfd_settime
A(timerfd_settime)
#endif
#ifdef __NR_times
A(times)
#endif
#ifdef __NR_tkill
A(tkill)
#endif
#ifdef __NR_truncate
A(truncate)
#endif
#ifdef __NR_ugetrlimit
A(ugetrlimit)
#endif
#ifdef __NR_umask
A(umask)
#endif
#ifdef __NR_uname
A(uname)
#endif
#ifdef __NR_unlink
A(unlink)
#endif
#ifdef __NR_unlinkat
A(unlinkat)
#endif
#ifdef __NR_utimensat
A(utimensat)
#endif
#ifdef __NR_utimes
A(utimes)
#endif
#ifdef __NR_vfork
A(vfork)
#endif
#ifdef __NR_wait4
A(wait4)
#endif
#ifdef __NR_waitid
A(waitid)
#endif
#ifdef __NR_write
A(write)
#endif
#ifdef __NR_writev
A(writev)
#endif
