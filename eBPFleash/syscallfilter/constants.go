package syscallfilter

const (
	syscallsFile     = "syscalls.json"
	capabilitiesFile = "capabilities.json"
	filePermissions  = 0644
)

var syscallToCapability = map[int]string{
	0: "CAP_READ_FILE",  //	read
	1: "CAP_WRITE_FILE", //	write

	2: "CAP_READ_FILE", //	open("/path/to/file", O_RDONLY)
	//	: "CAP_WRITE_FILE", 		//	open("/path/to/file", O_WRONLY)
	//	: "CAP_CREATE_FILE", 		//	open("/path/to/file", O_CREAT | O_WRONLY)

	3: "CAP_FILE",      //	close
	4: "CAP_READ_FILE", //	stat
	5: "CAP_READ_FILE", //	fstat
	6: "CAP_READ_FILE", //	lstat
	7: "CAP_FILE",      //	poll
	8: "CAP_FILE",      //	lseek

	9: "CAP_READ_FILE", //	mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset)
	// : "CAP_WRITE_FILE", 			//	mmap(NULL, size, PROT_WRITE, MAP_SHARED, fd, offset)
	// : "CAP_MEMORY_MANIPULATION", //	mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)

	10: "CAP_MEMORY_MANIPULATION", //	mprotect
	11: "CAP_MEMORY_MANIPULATION", //	munmap
	12: "CAP_MEMORY_MANIPULATION", //	brk
	13: "CAP_MODIFY_SYSTEM_STATE", //	rt_sigaction
	14: "CAP_MODIFY_SYSTEM_STATE", //	rt_sigprocmask
	15: "CAP_MODIFY_SYSTEM_STATE", //	rt_sigreturn
	16: "CAP_DIRECT_IO",           //	ioctl
	17: "CAP_READ_FILE",           //	pread64
	18: "CAP_WRITE_FILE",          //	pwrite64
	19: "CAP_READ_FILE",           //	readv
	20: "CAP_WRITE_FILE",          //	writev
	21: "CAP_READ_FILE",           //	access
	22: "CAP_MEMORY_MANIPULATION", //	pipe
	23: "CAP_FILE",                //	select
	24: "CAP_MODIFY_SYSTEM_STATE", //	sched_yield
	25: "CAP_MEMORY_MANIPULATION", //	mremap
	26: "CAP_FILE",                //	msync
	27: "CAP_MEMORY_MANIPULATION", //	mincore
	28: "CAP_MEMORY_MANIPULATION", //	madvise
	29: "CAP_MEMORY_MANIPULATION", //	shmget
	30: "CAP_MEMORY_MANIPULATION", //	shmat
	31: "CAP_MEMORY_MANIPULATION", //	shmctl
	32: "CAP_FILE",                //	dup
	33: "CAP_FILE",                //	dup2
	34: "CAP_MODIFY_SYSTEM_STATE", //	pause
	35: "CAP_MODIFY_SYSTEM_STATE", //	nanosleep
	36: "CAP_READ_SYSTEM_STATE",   //	getitimer
	37: "CAP_MODIFY_SYSTEM_STATE", //	alarm
	38: "CAP_MODIFY_SYSTEM_STATE", //	setitimer
	39: "CAP_READ_SYSTEM_STATE",   //	getpid
	40: "CAP_FILE",                //	sendfile
	41: "CAP_CONNECT_REMOTE",      //	socket
	42: "CAP_CONNECT_REMOTE",      //	connect
	43: "CAP_LISTEN_LOCAL",        //	accept
	44: "CAP_SEND_DATA",           //	sendto
	45: "CAP_RECEIVE_DATA",        //	recvfrom
	46: "CAP_SEND_DATA",           //	sendmsg
	47: "CAP_RECEIVE_DATA",        //	recvmsg
	48: "CAP_LISTEN_LOCAL",        //	shutdown
	49: "CAP_LISTEN_LOCAL",        //	bind
	50: "CAP_LISTEN_LOCAL",        //	listen
	51: "CAP_LISTEN_LOCAL",        //	getsockname
	52: "CAP_CONNECT_REMOTE",      //	getpeername
	53: "CAP_CONNECT_REMOTE",      //	socketpair
	54: "CAP_CONNECT_REMOTE",      //	setsockopt
	55: "CAP_CONNECT_REMOTE",      //	getsockopt
	56: "CAP_EXEC",                //	clone
	57: "CAP_EXEC",                //	fork
	58: "CAP_EXEC",                //	vfork
	59: "CAP_EXEC",                //	execve
	60: "CAP_TERMINATE_PROCESS",   //	exit
	61: "CAP_TERMINATE_PROCESS",   //	wait4
	62: "CAP_TERMINATE_PROCESS",   //	kill
	63: "CAP_READ_SYSTEM_STATE",   //	uname
	64: "CAP_MEMORY_MANIPULATION", //	semget
	65: "CAP_MEMORY_MANIPULATION", //	semop
	66: "CAP_MEMORY_MANIPULATION", //	semctl
	67: "CAP_MEMORY_MANIPULATION", //	shmdt
	68: "CAP_MEMORY_MANIPULATION", //	msgget
	69: "CAP_MEMORY_MANIPULATION", //	msgsnd
	70: "CAP_MEMORY_MANIPULATION", //	msgrcv
	71: "CAP_MEMORY_MANIPULATION", //	msgctl

	72: "CAP_READ_FILE", //	fcntl(fd, F_GETFD)
	//	: "CAP_WRITE_FILE"			// 	fcntl(fd, F_SETFD, flag)

	73:  "CAP_FILE_METADATA",       //	flock
	74:  "CAP_WRITE_FILE",          //	fsync
	75:  "CAP_WRITE_FILE",          //	fdatasync
	76:  "CAP_WRITE_FILE",          //	truncate
	77:  "CAP_WRITE_FILE",          //	ftruncate
	78:  "CAP_READ_FILE",           //	getdents
	79:  "CAP_READ_SYSTEM_STATE",   //	getcwd
	80:  "CAP_MODIFY_SYSTEM_STATE", //	chdir
	81:  "CAP_MODIFY_SYSTEM_STATE", //	fchdir
	82:  "CAP_FILE_METADATA",       //	rename
	83:  "CAP_CREATE_FILE",         //	mkdir
	84:  "CAP_CREATE_FILE",         //	rmdir
	85:  "CAP_CREATE_FILE",         //	creat
	86:  "CAP_CREATE_FILE",         //	link
	87:  "CAP_DELETE_FILE",         //	unlink
	88:  "CAP_CREATE_FILE",         //	symlink
	89:  "CAP_READ_FILE",           //  readlink
	90:  "CAP_FILE_METADATA",       //	chmod
	91:  "CAP_FILE_METADATA",       //	fchmod
	92:  "CAP_FILE_METADATA",       //	chown
	93:  "CAP_FILE_METADATA",       //	fchown
	94:  "CAP_FILE_METADATA",       //	lchown
	95:  "CAP_FILE_METADATA",       //	umask
	96:  "CAP_READ_SYSTEM_STATE",   //	gettimeofday
	97:  "CAP_RESOURCE_LIMITS",     //	getrlimit
	98:  "CAP_READ_SYSTEM_STATE",   //	getrusage
	99:  "CAP_READ_SYSTEM_STATE",   //	sysinfo
	100: "CAP_READ_SYSTEM_STATE",   //	times
	101: "CAP_MEMORY_MANIPULATION", //	ptrace
	102: "CAP_READ_SYSTEM_STATE",   //	getuid
	103: "CAP_READ_SYSTEM_STATE",   //	syslog
	104: "CAP_READ_SYSTEM_STATE",   //	getgid
	105: "CAP_MODIFY_SYSTEM_STATE", //	setuid
	106: "CAP_MODIFY_SYSTEM_STATE", //	setgid
	107: "CAP_READ_SYSTEM_STATE",   //	geteuid
	108: "CAP_READ_SYSTEM_STATE",   //	getegid
	109: "CAP_MODIFY_SYSTEM_STATE", //	setpgid
	110: "CAP_READ_SYSTEM_STATE",   //	getppid
	111: "CAP_READ_SYSTEM_STATE",   //	getpgrp
	112: "CAP_MODIFY_SYSTEM_STATE", //	setsid
	113: "CAP_MODIFY_SYSTEM_STATE", //	setreuid
	114: "CAP_MODIFY_SYSTEM_STATE", //	setregid
	115: "CAP_READ_SYSTEM_STATE",   //	getgroups
	116: "CAP_MODIFY_SYSTEM_STATE", //	setgroups
	117: "CAP_MODIFY_SYSTEM_STATE", //	setresuid
	118: "CAP_READ_SYSTEM_STATE",   //	getresuid
	119: "CAP_MODIFY_SYSTEM_STATE", //	setresgid
	120: "CAP_READ_SYSTEM_STATE",   //	getresgid
	121: "CAP_READ_SYSTEM_STATE",   //	getpgid
	122: "CAP_MODIFY_SYSTEM_STATE", //	setfsuid
	123: "CAP_MODIFY_SYSTEM_STATE", //	setfsgid
	124: "CAP_READ_SYSTEM_STATE",   //	getsid
	125: "CAP_READ_SYSTEM_STATE",   //	: "CAPget
	126: "CAP_MODIFY_SYSTEM_STATE", //	: "CAPset
	127: "CAP_READ_SYSTEM_STATE",   //	rt_sigpending
	128: "CAP_MODIFY_SYSTEM_STATE", //	rt_sigtimedwait
	129: "CAP_MODIFY_SYSTEM_STATE", //	rt_sigqueueinfo
	130: "CAP_MODIFY_SYSTEM_STATE", //	rt_sigsuspend
	131: "CAP_MODIFY_SYSTEM_STATE", //	sigaltstack
	132: "CAP_FILE_METADATA",       //	utime
	133: "CAP_CREATE_FILE",         //	mknod
	134: "CAP_EXEC",                //	uselib
	135: "CAP_MODIFY_SYSTEM_STATE", //	personality
	136: "CAP_READ_FILE",           //	ustat
	137: "CAP_READ_FILE",           //	statfs
	138: "CAP_READ_FILE",           //	fstatfs
	139: "CAP_READ_FILE",           //	sysfs
	140: "CAP_READ_SYSTEM_STATE",   //	getpriority
	141: "CAP_MODIFY_SYSTEM_STATE", //	setpriority
	142: "CAP_MODIFY_SYSTEM_STATE", //	sched_setparam
	143: "CAP_READ_SYSTEM_STATE",   //	sched_getparam
	144: "CAP_MODIFY_SYSTEM_STATE", //	sched_setscheduler
	145: "CAP_READ_SYSTEM_STATE",   //	sched_getscheduler
	146: "CAP_READ_SYSTEM_STATE",   //	sched_get_priority_max
	147: "CAP_READ_SYSTEM_STATE",   //	sched_get_priority_min
	148: "CAP_READ_SYSTEM_STATE",   //	sched_rr_get_interval
	149: "CAP_MEMORY_MANIPULATION", //	mlock
	150: "CAP_MEMORY_MANIPULATION", //	munlock
	151: "CAP_MEMORY_MANIPULATION", //	mlockall
	152: "CAP_MEMORY_MANIPULATION", //	munlockall
	153: "CAP_MODIFY_SYSTEM_STATE", //	vhangup
	154: "CAP_DIRECT_IO",           //	modify_ldt
	155: "CAP_MODIFY_SYSTEM_STATE", //	pivot_root
	156: "CAP_MODIFY_SYSTEM_STATE", //	_sysctl
	157: "CAP_MODIFY_SYSTEM_STATE", //	prctl
	158: "CAP_MODIFY_SYSTEM_STATE", //	arch_prctl
	159: "CAP_MODIFY_SYSTEM_STATE", //	adjtimex
	160: "CAP_RESOURCE_LIMITS",     //	setrlimit
	161: "CAP_MODIFY_SYSTEM_STATE", //	chroot
	162: "CAP_WRITE_FILE",          //	sync
	163: "CAP_MODIFY_SYSTEM_STATE", //	acct
	164: "CAP_MODIFY_SYSTEM_STATE", //	settimeofday
	165: "CAP_MODIFY_SYSTEM_STATE", //	mount
	166: "CAP_MODIFY_SYSTEM_STATE", //	umount2
	167: "CAP_MODIFY_SYSTEM_STATE", //	swapon
	168: "CAP_MODIFY_SYSTEM_STATE", //	swapoff
	169: "CAP_MODIFY_SYSTEM_STATE", //	reboot
	170: "CAP_MODIFY_SYSTEM_STATE", //	sethostname
	171: "CAP_MODIFY_SYSTEM_STATE", //	setdomainname
	172: "CAP_DIRECT_IO",           //	iopl
	173: "CAP_DIRECT_IO",           //	ioperm
	174: "CAP_MODIFY_SYSTEM_STATE", //	create_module
	175: "CAP_MODIFY_SYSTEM_STATE", //	init_module
	176: "CAP_MODIFY_SYSTEM_STATE", //	delete_module
	177: "CAP_READ_SYSTEM_STATE",   //	get_kernel_syms
	178: "CAP_MODIFY_SYSTEM_STATE", // query_module
	179: "CAP_FILE_METADATA",       //	quotactl
	180: "CAP_MODIFY_SYSTEM_STATE", //	nfsservctl
	181: "CAP_RECEIVE_DATA",        //	getpmsg
	182: "CAP_SEND_DATA",           //	putpmsg
	183: "CAP_MODIFY_SYSTEM_STATE", //	afs_syscall
	184: "CAP_MODIFY_SYSTEM_STATE", //	tuxcall
	185: "CAP_MODIFY_SYSTEM_STATE", //	security
	186: "CAP_READ_SYSTEM_STATE",   //	gettid
	187: "CAP_READ_FILE",           //	readahead
	188: "CAP_FILE_METADATA",       //	setxattr
	189: "CAP_FILE_METADATA",       //	lsetxattr
	190: "CAP_FILE_METADATA",       //	fsetxattr
	191: "CAP_READ_FILE",           //	getxattr
	192: "CAP_READ_FILE",           //	lgetxattr
	193: "CAP_READ_FILE",           //	fgetxattr
	194: "CAP_READ_FILE",           //	listxattr
	195: "CAP_READ_FILE",           //	llistxattr
	196: "CAP_READ_FILE",           //	flistxattr
	197: "CAP_FILE_METADATA",       //	removexattr
	198: "CAP_FILE_METADATA",       //	lremovexattr
	199: "CAP_FILE_METADATA",       //	fremovexattr
	200: "CAP_TERMINATE_PROCESS",   //	tkill
	201: "CAP_READ_SYSTEM_STATE",   //	time
	202: "CAP_MEMORY_MANIPULATION", //	futex
	203: "CAP_MODIFY_SYSTEM_STATE", //	sched_setaffinity
	204: "CAP_READ_SYSTEM_STATE",   //	sched_getaffinity
	205: "CAP_DIRECT_IO",           //	set_thread_area
	206: "CAP_DIRECT_IO",           //	io_setup
	207: "CAP_DIRECT_IO",           //	io_destroy
	208: "CAP_DIRECT_IO",           //	io_getevents
	209: "CAP_DIRECT_IO",           //	io_submit
	210: "CAP_DIRECT_IO",           //	io_cancel
	211: "CAP_MEMORY_MANIPULATION", //	get_thread_area
	212: "CAP_FILE",                //	lookup_dcookie
	213: "CAP_MEMORY_MANIPULATION", //	epoll_create
	214: "CAP_MEMORY_MANIPULATION", //	epoll_ctl_old
	215: "CAP_MEMORY_MANIPULATION", //	epoll_wait_old
	216: "CAP_MEMORY_MANIPULATION", //	remap_file_pages
	217: "CAP_READ_FILE",           //	getdents64
	218: "CAP_MEMORY_MANIPULATION", //	set_tid_address
	219: "CAP_MODIFY_SYSTEM_STATE", //	restart_syscall
	220: "CAP_MEMORY_MANIPULATION", //	semtimedop
	221: "CAP_FILE_METADATA",       //	fadvise64
	222: "CAP_MODIFY_SYSTEM_STATE", //	timer_create
	223: "CAP_MODIFY_SYSTEM_STATE", //	timer_settime
	224: "CAP_READ_SYSTEM_STATE",   //	timer_gettime
	225: "CAP_READ_SYSTEM_STATE",   //	timer_getoverrun
	226: "CAP_MODIFY_SYSTEM_STATE", //	timer_delete
	227: "CAP_MODIFY_SYSTEM_STATE", //	clock_settime
	228: "CAP_READ_SYSTEM_STATE",   //	clock_gettime
	229: "CAP_MODIFY_SYSTEM_STATE", //	clock_getres
	230: "CAP_MODIFY_SYSTEM_STATE", //	clock_nanosleep
	231: "CAP_TERMINATE_PROCESS",   //	exit_group
	232: "CAP_MEMORY_MANIPULATION", //	epoll_wait
	233: "CAP_MEMORY_MANIPULATION", //	epoll_ctl
	234: "CAP_TERMINATE_PROCESS",   //	tgkill
	235: "CAP_FILE_METADATA",       //	utimes
	236: "CAP_MODIFY_SYSTEM_STATE", //	vserver
	237: "CAP_MEMORY_MANIPULATION", //	mbind
	238: "CAP_MEMORY_MANIPULATION", //	set_mempolicy
	239: "CAP_READ_SYSTEM_STATE",   //	get_mempolicy
	240: "CAP_FILE",                //	mq_open
	241: "CAP_DELETE_FILE",         //	mq_unlink
	242: "CAP_SEND_DATA",           //	mq_timedsend
	243: "CAP_RECEIVE_DATA",        //	mq_timedreceive
	244: "CAP_MODIFY_SYSTEM_STATE", //	mq_notify
	245: "CAP_MODIFY_SYSTEM_STATE", //	mq_getsetattr
	246: "CAP_MODIFY_SYSTEM_STATE", //	kexec_load
	247: "CAP_TERMINATE_PROCESS",   //	waitid
	248: "CAP_MODIFY_SYSTEM_STATE", //	add_key
	249: "CAP_MODIFY_SYSTEM_STATE", //	request_key
	250: "CAP_MODIFY_SYSTEM_STATE", //	keyctl
	251: "CAP_MODIFY_SYSTEM_STATE", //	ioprio_set
	252: "CAP_READ_SYSTEM_STATE",   //	ioprio_get
	253: "CAP_FILE",                //	inotify_init
	254: "CAP_FILE_METADATA",       //	inotify_add_watch
	255: "CAP_FILE_METADATA",       //	inotify_rm_watch
	256: "CAP_MEMORY_MANIPULATION", //	migrate_pages

	257: "CAP_READ_FILE", //	openat(fd, "file", O_RDONLY)
	//	 : "CAP_WRITE_FILE", 		//	openat(fd, "file", O_WRONLY)
	//	 : "CAP_CREATE_FILE", 		//	openat(fd, "file", O_CREAT | O_WRONLY)

	258: "CAP_CREATE_FILE",         //	mkdirat
	259: "CAP_CREATE_FILE",         //	mknodat
	260: "CAP_FILE_METADATA",       //	fchownat
	261: "CAP_FILE_METADATA",       //	futimesat
	262: "CAP_READ_FILE",           //	newfstatat
	263: "CAP_DELETE_FILE",         //	unlinkat
	264: "CAP_FILE_METADATA",       //	renameat
	265: "CAP_CREATE_FILE",         //	linkat
	266: "CAP_CREATE_FILE",         //	symlinkat
	267: "CAP_READ_FILE",           //	readlinkat
	268: "CAP_FILE_METADATA",       //	fchmodat
	269: "CAP_READ_FILE",           //	faccessat
	270: "CAP_READ_FILE",           //	pselect6
	271: "CAP_READ_FILE",           //	ppoll
	272: "CAP_MODIFY_SYSTEM_STATE", //	unshare
	273: "CAP_MEMORY_MANIPULATION", //	set_robust_list
	274: "CAP_MEMORY_MANIPULATION", //	get_robust_list
	275: "CAP_FILE",                //	splice
	276: "CAP_READ_FILE",           //	tee
	277: "CAP_WRITE_FILE",          //	sync_file_range
	278: "CAP_MEMORY_MANIPULATION", //	vmsplice
	279: "CAP_MEMORY_MANIPULATION", //	move_pages
	280: "CAP_FILE_METADATA",       //	utimensat
	281: "CAP_MEMORY_MANIPULATION", //	epoll_pwait
	282: "CAP_MODIFY_SYSTEM_STATE", //	signalfd
	283: "CAP_MODIFY_SYSTEM_STATE", //	timerfd_create
	284: "CAP_MODIFY_SYSTEM_STATE", //	eventfd
	285: "CAP_WRITE_FILE",          //	fallocate
	286: "CAP_MODIFY_SYSTEM_STATE", //	timerfd_settime
	287: "CAP_READ_SYSTEM_STATE",   //	timerfd_gettime
	288: "CAP_LISTEN_LOCAL",        //	accept4
	289: "CAP_MODIFY_SYSTEM_STATE", //	signalfd4
	290: "CAP_MODIFY_SYSTEM_STATE", //	eventfd2
	291: "CAP_MEMORY_MANIPULATION", //	epoll_create1

	292: "CAP_READ_FILE", //	dup3(fd, newfd, O_RDONLY)
	//	 : "CAP_WRITE_FILE", 		//	dup3(fd, newfd, O_WRONLY)

	293: "CAP_MEMORY_MANIPULATION", //	pipe2
	294: "CAP_FILE",                //	inotify_init1
	295: "CAP_READ_FILE",           //	preadv
	296: "CAP_WRITE_FILE",          //	pwritev
	297: "CAP_MODIFY_SYSTEM_STATE", //	rt_tgsigqueueinfo
	298: "CAP_MODIFY_SYSTEM_STATE", //	perf_event_open
	299: "CAP_RECEIVE_DATA",        //	recvmmsg
	300: "CAP_FILE",                //	fanotify_init
	301: "CAP_FILE_METADATA",       //	fanotify_mark
	302: "CAP_RESOURCE_LIMITS",     //	prlimit64
	303: "CAP_READ_FILE",           //	name_to_handle_at

	304: "CAP_READ_FILE", //	open_by_handle_at(mnt_fd, handle, O_RDONLY)
	//   : "CAP_WRITE_FILE", 		//	open_by_handle_at(mnt_fd, handle, O_WRONLY)

	305: "CAP_MODIFY_SYSTEM_STATE", //	clock_adjtime
	306: "CAP_WRITE_FILE",          //	syncfs
	307: "CAP_SEND_DATA",           //	sendmmsg
	308: "CAP_MODIFY_SYSTEM_STATE", //	setns
	309: "CAP_READ_SYSTEM_STATE",   //	getcpu
	310: "CAP_MEMORY_MANIPULATION", //	process_vm_readv
	311: "CAP_MEMORY_MANIPULATION", //	process_vm_writev
	312: "CAP_READ_SYSTEM_STATE",   //	kcmp
	313: "CAP_MODIFY_SYSTEM_STATE", //	finit_module
	314: "CAP_MODIFY_SYSTEM_STATE", //	sched_setattr
	315: "CAP_READ_SYSTEM_STATE",   //	sched_getattr
	316: "CAP_FILE_METADATA",       //	renameat2
	317: "CAP_MODIFY_SYSTEM_STATE", //	seccomp
	318: "CAP_READ_SYSTEM_STATE",   //	getrandom
	319: "CAP_MEMORY_MANIPULATION", //	memfd_create
	320: "CAP_MODIFY_SYSTEM_STATE", //	kexec_file_load
	321: "CAP_MODIFY_SYSTEM_STATE", //	bpf
	322: "CAP_EXEC",                //	execveat
	323: "CAP_MEMORY_MANIPULATION", //	userfaultfd
	324: "CAP_MEMORY_MANIPULATION", //	membarrier
	325: "CAP_MEMORY_MANIPULATION", //	mlock2
	326: "CAP_FILE",                //	copy_file_range
	327: "CAP_READ_FILE",           //	preadv2
	328: "CAP_WRITE_FILE",          //	pwritev2
	329: "CAP_MEMORY_MANIPULATION", //	pkey_mprotect
	330: "CAP_MEMORY_MANIPULATION", //	pkey_alloc
	331: "CAP_MEMORY_MANIPULATION", //	pkey_free
	332: "CAP_READ_FILE",           //	statx
	333: "CAP_DIRECT_IO",           //	io_pgetevents
	334: "CAP_MODIFY_SYSTEM_STATE", //	rseq
	424: "CAP_MODIFY_SYSTEM_STATE", //	pidfd_send_signal
	425: "CAP_DIRECT_IO",           //	io_uring_setup
	426: "CAP_DIRECT_IO",           //	io_uring_enter
	427: "CAP_DIRECT_IO",           //	io_uring_register
	428: "CAP_READ_FILE",           //	open_tree
	429: "CAP_MODIFY_SYSTEM_STATE", //	move_mount
	430: "CAP_MODIFY_SYSTEM_STATE", //	fsopen
	431: "CAP_MODIFY_SYSTEM_STATE", //	fsconfig
	432: "CAP_MODIFY_SYSTEM_STATE", //	fsmount
	433: "CAP_MODIFY_SYSTEM_STATE", //	fspick
	434: "CAP_MODIFY_SYSTEM_STATE", //	pidfd_open
	435: "CAP_EXEC",                //	clone3
	436: "CAP_FILE",                //	close_range

	437: "CAP_READ_FILE", //	openat2(fd, "file", {flags=O_RDONLY})
	//	 : "CAP_WRITE_FILE", 		//	openat2(fd, "file", {flags=O_WRONLY})
	//	 : "CAP_CREATE_FILE", 		//	openat2(fd, "file", {flags=O_WRONLY | O_CREAT})

	438: "CAP_READ_SYSTEM_STATE",   //	pidfd_getfd
	439: "CAP_READ_FILE",           //	faccessat2
	440: "CAP_MEMORY_MANIPULATION", //	process_madvise
	441: "CAP_MEMORY_MANIPULATION", //	epoll_pwait2
	442: "CAP_MODIFY_SYSTEM_STATE", //	mount_setattr
	443: "CAP_MODIFY_SYSTEM_STATE", //	quotactl_fd
	444: "CAP_MODIFY_SYSTEM_STATE", //	landlock_create_ruleset
	445: "CAP_MODIFY_SYSTEM_STATE", //	landlock_add_rule
	446: "CAP_MODIFY_SYSTEM_STATE", //	landlock_restrict_self
	447: "CAP_MEMORY_MANIPULATION", //	memfd_secret
	448: "CAP_MEMORY_MANIPULATION", //	process_mrelease
	449: "CAP_MEMORY_MANIPULATION", //	futex_waitv
	450: "CAP_MEMORY_MANIPULATION", //	set_mempolicy_home_node
	451: "CAP_READ_FILE",           //	cachestat
	452: "CAP_FILE_METADATA",       //	fchmodat2
	453: "CAP_MEMORY_MANIPULATION", //	map_shadow_stack
	454: "CAP_MEMORY_MANIPULATION", //	futex_wake
	455: "CAP_MEMORY_MANIPULATION", //	futex_wait
	456: "CAP_MEMORY_MANIPULATION", //	futex_requeue

}
