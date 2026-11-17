/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_LAB_LOOPBACK_HOST_H
#define STEER_LAB_LOOPBACK_HOST_H
/* Shared disposable Linux lab host; vless=0 SOCKS5, vless=1 VLESS plain v0. */
int steer_lab_loopback_main(int argc, char **argv, int vless);
int steer_prototype_main(int argc, char **argv);
#endif
