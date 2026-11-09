package main

import "syscall"

var syscallAttributes = syscall.SysProcAttr{Setsid: true}
