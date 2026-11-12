#!/usr/bin/env bash
# systemd-detect-virt reports bare metal as "none" with exit status 1.
is_native_target() {
    local virtualization status
    if virtualization=$(systemd-detect-virt); then
        status=0
    else
        status=$?
    fi
    [[ $status == 1 && $virtualization == none ]]
}
