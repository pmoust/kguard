/*
 * kGuard Copyright (C) 2010 Columbia University
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in November 2010.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __KGUARD_H__
#define __KGUARD_H__

#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "basic-block.h"
#include "rtl.h"
#include "emit-rtl.h"
#include "gcc-plugin.h"
#include "tree.h"
#include "tree-pass.h"
#include "plugin-version.h"
#include "config/i386/i386-protos.h"

/* plugin name and version */
#define NAME		"kguard"
#define VER		"3.141592alpha"

/* constants */
#define BASE10 		10	/* 10th base				*/
#define BASE100 	100	/* 100th base				*/
#define GCC45_PREF	"4.5"	/* GCC 4.5.x series prefix		*/
#define VER_DELIM	'.'	/* version delimiter			*/
#define HTAB_SZ_DFL	16	/* default hash table size		*/
#define STUB_STR	"stub"	/* `stub' option (argument) literal	*/
#define NOP_STR		"nop"	/* `nop' option (argument) literal	*/
#define NOP_DFL		16	/* `nop' default value			*/
#define RETPROT_STR	"retprot"/* `retprot' option (argument) literal	*/
#define RETPROT_DFL	1	/* `retprot' default value		*/
#define S_REG		5	/* number of the register to be spilled
				   (hard register)			*/

#ifdef	DEBUG
#define	LOG_STR		"log"	/* `log' option (argument) literal	*/
#endif	/* LOG_STR */

#if	linux && __amd64__
#define STUB_DFL	"panic"		/* `stub' default value		*/
#define	KADDR_DFL	0x0		/* kaddr default value		*/
#elif	linux && __i386__
#define STUB_DFL	"panic"		/* `stub' default value		*/
#define	KADDR_DFL	0xC0000000	/* kaddr default value		*/
#else
#error	"[!] Unsupported platform"	/* unknown platform		*/
#endif	/* STUB_DFL & KADDR_DFL */

/* differentiate based on the machine's ISA (32- vs 64-bit) */
#if	__SIZEOF_POINTER__ == 8
#define	MMODE		DImode		/* double integer; 8-bytes	*/
#else
#define	MMODE		SImode		/* single integer; 4-bytes	*/
#endif	/* MMODE */

/* compiler directives for branch prediction */
#define	likely(x) 	__builtin_expect((x), 1)
#define	unlikely(x)	__builtin_expect((x), 0)

enum {
	SUCC = 0,	/* success; return value 	*/
	FAIL = 1	/* failed; return value		*/
};

enum {
	UNSAFE_INSTR	= 0,	/* constant; indicates the instrumentation of
				   an unsafe instruction		*/
	SAFE_M_INSTR	= 1,	/* constant; indicates the instrumentation of 
				   a safe instruction (memory)		*/
	SAFE_R_INSTR	= 2,	/* constant; indicates the instrumentation of 
				   a safe instruction (register)	*/
	SAFE_RET_INSTR	= 3,	/* constant; indicates the instrumentation of
				   a safe return instruction (memory)	*/
	NO_INSTR	= 4	/* constant; indicates that a branching	
				   instruction is not instrumented	*/
};

#endif /* __KGUARD_H__ */
