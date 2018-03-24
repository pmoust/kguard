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

#include <bsd/stdlib.h>
#include "kguard.h"

/* 
 * TODO:
 * 	- Add support for GCC v4.7 (or later).
 * 	- Add something useful in `plugin_info' help (pinfo.help).
 */

/* function declarations */
unsigned int branchprot_instrument(void);

/* assert GPL compatibility */
int __attribute__ ((visibility("default"))) plugin_is_GPL_compatible; 

/* plugin information structure */
struct plugin_info __attribute__ ((visibility("default")))
pinfo = {
	.version	= VER,
	.help		= NULL
};

/* descriptor for the new pass provided by the plugin */
struct rtl_opt_pass __attribute__ ((visibility("default")))
pass_branchprot = {{ 
	RTL_PASS,
	NAME,
	NULL,
	branchprot_instrument,
	NULL,
	NULL,
	0,
	TV_NONE,
	PROP_rtl,
	0, 0, 0, 0
}};

/* plugin versioning structure */
static struct plugin_gcc_version
pver = {
	.basever	= "4.5.0",
	.datestamp	= "",
	.devphase	= "",
	.revision	= "",
	.configuration_arguments = ""
};

/* kernel starting address */
static int kaddr	= KADDR_DFL;

/* stub; run-time violation handler (address or symbol) */
static const char *stub	= STUB_DFL;

/* NOP sled size; upper bound */
static size_t nop	= NOP_DFL;

/* retprot flag */
static size_t retprot	= RETPROT_DFL;

/* compatibility mode (needed for GCC 4.5.x series) */
static int compat	= 0;

#ifdef	DEBUG
/* log filename */
static char *log	= NULL;

/* logfile */
static FILE *flog	= NULL;

/*
 * start the auditing process
 *
 * Open the logfile in append mode.
 */
static void
openlog(void)
{
	/* check if a filename for logging has been specified */
	if (log != NULL) {
		/* open the logfile in appending mode */
		if (likely((flog = fopen(log, "a")) != NULL))
			/* success */
			/* dump information regarding the translation unit */
			(void)fprintf(flog, "[/F]:%s\n",
				IDENTIFIER_POINTER(DECL_NAME(cfun->decl)));
		else
			/* failed */
			(void)fprintf(stderr,
				"%s: failed while trying to open %s (%s)\n",
					NAME, log, xstrerror(errno));
	}
}

/*
 * terminate the auditing process
 *
 * Close the logfile.
 */
static void
closelog(void)
{
	/* check if logging has been enabled */
	if (flog != NULL) {
		/* dump information regarding the translation unit */
		(void)fprintf(flog, "[F/]:%s\n",
				IDENTIFIER_POINTER(DECL_NAME(cfun->decl)));

		/* cleanup */
		(void)fclose(flog);
	}
}

/*
 * perform the actual logging
 *
 * Print the RTL expression of the inspected instruction; in case of
 * instrumented instructions print an additional discriminator (i.e.,
 * `M' for branches via an unsafe memory location, and `SM`/`R` for
 * branches via safe memory locations or registers).
 *
 * insn:	the instruction to log
 * 		(e.g., a call_insn or jump_insn expression)
 * type:	the type of the instrumentation
 * 		(e.g., no instrumentation, safe, unsafe)
 */
static void
commitlog(const rtx insn, const size_t type)
{
	/* check if logging has been enabled */
	if (flog != NULL) {
		/* differentiate based on the instrumentation type */
		switch (type) {
			case SAFE_RET_INSTR:
				/* 
				 * discriminator for instrumented instructions;
				 * branch via a safe memory location (return)
				 */
				(void)fprintf(flog, "[SM-ret] ");
				break;

			case UNSAFE_INSTR:
				/* 
				 * discriminator for instrumented instructions;
				 * branch via an unsafe memory location
				 */
				(void)fprintf(flog, "[M] ");
				break;

			case SAFE_M_INSTR:
				/* 
				 * discriminator for instrumented instructions;
				 * branch via safe a memory location
				 */
				(void)fprintf(flog, "[SM] ");
				break;
			
			case SAFE_R_INSTR:
				/* 
				 * discriminator for instrumented instructions;
				 * branch via register
				 */
				(void)fprintf(flog, "[R] ");
				break;

			case NO_INSTR:
			default:
				/* default; make the compiler happy */
				break;
		}

		/* dump the instruction */
		print_rtl_single(flog, insn);
	}
}
#endif /* DEBUG */

/*
 * check if an expression contains an indirect call
 * (e.g., as a sub-expression) in a DFS-like manner
 *
 * NOTE: It assumes that we can have only up to one
 * call sub-expression (i.e., call_insn specific).
 *
 * expr:	the expression to check
 *
 * returns:	the indirect call sub-expression
 * 		(if expr contains one), NULL otherwise
 */
static const rtx
contains_indirect_call(const rtx expr)
{
	size_t i; 	/* iterator */
	rtx res = NULL;	/* return value */

	/* quick reject; the expression is irrelevant */
	if (expr == NULL || GET_RTX_CLASS(GET_CODE(expr)) != RTX_EXTRA)
		return NULL;

	/* a call expression found; check if it is an indirect call */
	if (unlikely(GET_CODE(expr) == CALL && 
		GET_RTX_CLASS(GET_CODE(XEXP(XEXP(expr, 0), 0)))
		 != RTX_CONST_OBJ))
		/* indirect call found; return it (ptr) */
		return expr;

	/* iterate all the sub-expressions */
	for (i = 0; i < GET_RTX_LENGTH(GET_CODE(expr)); i++) {
		/* extract the sub-expression and inspect it */
		res = contains_indirect_call(XEXP(expr, i));

		/* 
		 * found an indirect call sub-expression;
		 * no need to check the rest
		 */
		if (unlikely(res != NULL))
			break;
	}

	/* return the result */
	return res;
}

/*
 * check if an expression contains an indirect jump or
 * return (e.g., as a sub-expression) in a DFS-like manner
 *
 * NOTE: It assumes that we can have only up to one
 * jump sub-expression (i.e., jump_insn specific).
 *
 * expr:	the expression to check
 *
 * returns:	the indirect jump sub-expression
 * 		(if expr contains one), NULL otherwise
 */
static const rtx
contains_indirect_jump(const rtx expr)
{
	int i; 		/* iterator */
	rtx res = NULL;	/* return value */

	/* quick reject; the expression is irrelevant */
	if (expr == NULL ||
		GET_CODE(expr) == USE || 
		GET_CODE(expr) == CLOBBER ||
		GET_CODE(expr) == ASM_OPERANDS)
		return NULL;
	
	/* a return/eh_return expression found */
	if ((retprot == 1) &&
		((GET_CODE(expr) == EH_RETURN)		||
#if	GCCPLUGIN_VERSION >= 4007
		/* GCC 4.7.x series have more than one `return' expression */
		(GET_CODE(expr) == SIMPLE_RETURN)	||
#endif
		(GET_CODE(expr) == RETURN)))
		/* return it (ptr) */
		return expr;

	/* a set expression found; check if it is an indirect jump */
	if (GET_CODE(expr) == SET &&
			(MEM_P(XEXP(expr, 1)) || REG_P(XEXP(expr, 1))))
		/* indirect jump found; return it (ptr) */
		return expr;

	/* expression vector */
	if (GET_CODE(expr) == PARALLEL) {
		/* iterate all the sub-expressions */
		for (i = 0; i < XVECLEN(expr, 0); i++) {
			/* extract the sub-expression and inspect it */
			res = contains_indirect_jump(XVECEXP(expr, 0, i));

			/* 
			 * found an indirect jump sub-expression;
			 * no need to check the rest
			 */
			if (unlikely(res != NULL))
				break;
		}
	}

	/* return the result */
	return res;
}

/*
 * instrument an indirect branch;
 * The branch target should be stored into:
 * 	i.	a register.
 * 	ii.	a "safe" memory location (i.e., see safe_ea() for more
 * 		information regarding what we consider to be a safe
 * 		memory location).
 *
 * Split the BB that contains the call_insn or jump_insn into two new BBs
 * (the split is done just before the branch), and insert one more BB in
 * between that contains the confinement code.
 *
 * branch_insn:	the call_insn/jump_insn expression
 * branch:	the call/jump expression
 * type:	the type of the instruction (i.e., call_insn or jump_insn)
 */
static void
instr_branch_safe(const rtx branch_insn, const rtx branch, const size_t type)
{
	size_t i;		/* iterator */
	basic_block bbranch_bb;	/* basic block that contains the code
				   before the branch */
	rtx branch_prev;	/* expression before the branch */
	rtx flags_reg;		/* condition code register */
	rtx btarget;		/* expression for the branch target */
	rtx ksaddr;		/* kernel starting address */
	rtx nop_pattern;	/* NOP pattern */
	rtx cmp;		/* compare expression */
	rtx jmp;		/* jump expression */
	rtx branch_lbl;		/* label expression */
	rtx vsaddr;		/* violation handler */
	
	/* machine condition code mode */
	enum machine_mode cmpmode;

	/* split the basic block before the branch expression */
	branch_prev	= PREV_INSN(branch_insn);
	bbranch_bb	= BLOCK_FOR_INSN(branch_prev);
	split_block(bbranch_bb, branch_prev);

	/* 
	 * get a new label for the branch block
	 * (i.e., before the branch instruction in the new block)
	 */
	branch_lbl	= emit_label_before(gen_label_rtx(), branch_insn);

	/* rtx expression that computes the branch target of the branch */
	if (type == CALL_INSN)
		/* call_insn expression */
		btarget	= copy_rtx(XEXP(XEXP(branch, 0), 0));
	else if (type == JUMP_INSN)
		/* jump_insn expression */
		btarget	= copy_rtx(XEXP(branch, 1));
	else
		/* return/eh_return expression */
		btarget = gen_rtx_MEM(MMODE, gen_rtx_REG(MMODE,
							STACK_POINTER_REGNUM));

	/* constant rtx expression with the base address of the kernel */
	ksaddr		= GEN_INT(kaddr);

	/* rtx expression with the appropriate condition code mode */
#if	linux && __amd64__
	cmpmode		= SELECT_CC_MODE(LT, btarget, ksaddr);
#elif	linux && __i386__
	cmpmode		= SELECT_CC_MODE(GEU, btarget, ksaddr);
#else
	#error  "[!] Unsupported platform"	/* unknown platform */
#endif

	/* rtx expression for the condition register (flags) */
	flags_reg	= gen_rtx_REG(cmpmode, FLAGS_REG);
	
	/* generate the random NOP sled */
	nop_pattern	= branch_prev;
	for (i = 0; i <= arc4random_uniform(nop + 1); i++)
		nop_pattern = emit_insn_after(gen_nop(), nop_pattern);
	
	/* generate a compare instruction */
	cmp		= emit_insn_after(gen_rtx_SET(VOIDmode, flags_reg,
				gen_rtx_COMPARE(cmpmode, btarget, ksaddr)),
				nop_pattern);
	
	/* generate a jump instruction */
	jmp		= emit_jump_insn_after(gen_rtx_SET(VOIDmode,
				/* rtx expression for the PC */
				pc_rtx,
				gen_rtx_IF_THEN_ELSE(VOIDmode,
#if	linux && __amd64__
				gen_rtx_LT(VOIDmode, flags_reg, const0_rtx),
#elif	linux && __i386__
				gen_rtx_GEU(VOIDmode, flags_reg, const0_rtx),
#else
	#error  "[!] Unsupported platform"	/* unknown platform */
#endif
				/* 
				 * goto the branch instruction if target branch
				 * address >= kernel base
				 */
				gen_rtx_LABEL_REF(VOIDmode, branch_lbl),
				pc_rtx)),
				cmp);
	
	/* link the jump instruction with the branch label */
	JUMP_LABEL(jmp)	=  branch_lbl;
	LABEL_NUSES(branch_lbl)++;
	
	/* run-time violation handler; stub */
	vsaddr		= gen_rtx_SYMBOL_REF(Pmode, stub);
	SYMBOL_REF_FLAGS(vsaddr) |= 
		(SYMBOL_FLAG_FUNCTION | SYMBOL_FLAG_EXTERNAL);

	/* generate the "fix" code */
	(void)emit_insn_after(gen_rtx_SET(VOIDmode,
			copy_rtx(btarget),
			vsaddr),
			jmp);
}

/* 
 * generate a "pop" expression
 *
 * Store the top of the stack into a destination operand.
 *
 * dst:		the destination operand
 *
 * returns:	the "pop" expression
 */
static const rtx
gen_rtx_pop(const rtx dst)
{
	/* we need different handling based on the GCC version */
	if (compat)
		/* really ugly; clopied from gen_popsi1() :) */
		return gen_rtx_PARALLEL(VOIDmode,
			gen_rtvec(2,
				gen_rtx_SET(VOIDmode,
					dst,
					gen_rtx_MEM(MMODE,
						gen_rtx_REG(MMODE,
							STACK_POINTER_REGNUM))),
				gen_rtx_SET(VOIDmode,
					gen_rtx_REG(MMODE,
						STACK_POINTER_REGNUM),
					gen_rtx_PLUS(MMODE,
						gen_rtx_REG(MMODE,
							STACK_POINTER_REGNUM),
						GEN_INT(__SIZEOF_POINTER__)))));
	else
		return gen_rtx_SET(VOIDmode,
				dst,
				gen_rtx_MEM(MMODE, gen_rtx_POST_INC(Pmode,
					gen_rtx_REG(MMODE,
						STACK_POINTER_REGNUM))));
}

/*
 * instrument an unsafe indirect branch;
 * the EA of the branch target is stored into an "unsafe" memory location
 * (i.e., a memory location referenced via the general purpose register (GPR),
 * or via some GPR registers along with some constant arithmetic operations).
 *
 * Split the BB that contains the branch instruction into two new BBs (the
 * split is done just before the branch), and insert one more BB in between that
 * contain the confinement code. The difference of instr_branch_unsafe() and
 * instr_branch_safe() is that the former confines also the location that the
 * EA of the branch target is stored.
 *
 * branch_insn:	the call_insn/jump_insn expression
 * branch:	the call/jump expression
 * ea:		expression that computes the location of the EA
 * 		of the branch target
 * type:	the type of the instruction (i.e., call_insn or jump_insn)
 */
static void
instr_branch_unsafe(const rtx branch_insn,
		const rtx branch,
		const rtx ea,
		const size_t type)
{
	size_t i;		/* iterator */
	basic_block bbranch_bb;	/* basic block that contains the code
				   before the branch */
	rtx branch_prev;	/* expression before the branch */
	rtx flags_reg;		/* condition code register */
	rtx flags_reg_ea;	/* condition code register; EA check */
	rtx btarget;		/* expression for the branch target */
	rtx btarget_ea;		/* expression for the memory location that
				   holds the branch target */
	rtx ksaddr;		/* kernel starting address */
	rtx ksaddr_ea;		/* kernel starting address; EA check */
	rtx nop_pattern;	/* NOP pattern */
	rtx cmp;		/* compare expression */
	rtx cmp_ea;		/* compare expression; EA check */
	rtx jmp;		/* jump expression */
	rtx jmp_ea;		/* jump expression; EA check */
	rtx branch_lbl;		/* label expression */
	rtx branch_chk_lbl;	/* label expression */
	rtx vsaddr;		/* violation handler */
	rtx push;		/* push expression */
	rtx pop;		/* pop expression */
	rtx pop_fix;		/* pop expression */
	rtx sreg;		/* spilled register */
	
	/* machine condition code modes */
	enum machine_mode cmpmode, cmpmode_ea;
	
	/* split the basic block before the branch expression */
	branch_prev	= PREV_INSN(branch_insn);
	bbranch_bb	= BLOCK_FOR_INSN(branch_prev);
	split_block(bbranch_bb, branch_prev);

	/* 
	 * get a new label for the branch block
	 * (i.e., before the branch instruction in the new block)
	 */
	branch_lbl	= emit_label_before(gen_label_rtx(), branch_insn);
	
	/* 
	 * get a new label for the branch check block
	 * (i.e., before branch_lbl in the new block)
	 */
	branch_chk_lbl	= emit_label_before(gen_label_rtx(), branch_lbl);

	/* rtx expression that computes the branch target of the branch */
	if (type == CALL_INSN)
		/* call_insn expression */
		btarget	= copy_rtx(XEXP(XEXP(branch, 0), 0));
	else
		/* jump_insn expression */
		btarget	= copy_rtx(XEXP(branch, 1));

	/* 
	 * rtx expression that computes the register
	 * that holds the branch target (i.e., the EA);
	 */
	btarget_ea	= gen_rtx_REG(MMODE, S_REG);
	
	/* constant rtx expression with the base address of the kernel */
	ksaddr		= GEN_INT(kaddr);
	
	/* 
	 * constant rtx expression with the base address of the kernel;
	 * EA check
	 */
	ksaddr_ea	= GEN_INT(kaddr);
	
#if	linux && __amd64__
	/* rtx expression with the appropriate condition code mode */
	cmpmode		= SELECT_CC_MODE(LT, btarget, ksaddr);

	/* rtx expression with the appropriate condition code mode; EA check */
	cmpmode_ea	= SELECT_CC_MODE(LT, btarget_ea, ksaddr_ea);
#elif	 linux && __i386__
	/* rtx expression with the appropriate condition code mode */
	cmpmode		= SELECT_CC_MODE(GEU, btarget, ksaddr);

	/* rtx expression with the appropriate condition code mode; EA check */
	cmpmode_ea	= SELECT_CC_MODE(GEU, btarget_ea, ksaddr_ea);
#else
	#error  "[!] Unsupported platform"	/* unknown platform */
#endif

	/* rtx expression for the condition register (flags) */
	flags_reg	= gen_rtx_REG(cmpmode, FLAGS_REG);
	
	/* rtx expression for the condition register (flags); EA check */
	flags_reg_ea	= gen_rtx_REG(cmpmode_ea, FLAGS_REG);
	
	/* run-time violation handler; stub */
	vsaddr		= gen_rtx_SYMBOL_REF(Pmode, stub);
	SYMBOL_REF_FLAGS(vsaddr) |= 
		(SYMBOL_FLAG_FUNCTION | SYMBOL_FLAG_EXTERNAL);
	
	/* generate the random NOP sled */
	nop_pattern	= branch_prev;
	for (i = 0; i <= arc4random_uniform(nop + 1); i++)
		nop_pattern = emit_insn_after(gen_nop(), nop_pattern);
	
	/* spill a register for holding the EA of the branch target */
	push		= emit_insn_after(gen_rtx_SET(VOIDmode,
				gen_rtx_MEM(Pmode,
				gen_rtx_PRE_DEC(Pmode, stack_pointer_rtx)),
				copy_rtx(btarget_ea)),
				nop_pattern);
	
	/* compute the EA of the branch target into the spilled register */
	sreg		= emit_insn_after(gen_rtx_SET(VOIDmode,
				copy_rtx(btarget_ea),
				copy_rtx(ea)),
				push);

	/* generate a compare instruction; check the memory location first */
	cmp_ea		= emit_insn_after(gen_rtx_SET(VOIDmode, flags_reg_ea,
				gen_rtx_COMPARE(cmpmode_ea,
					btarget_ea,
					ksaddr_ea)),
				sreg);
	
	/* generate a jump instruction */
	jmp_ea		= emit_jump_insn_after(gen_rtx_SET(VOIDmode,
				/* rtx expression for the PC */
				pc_rtx,
				gen_rtx_IF_THEN_ELSE(VOIDmode,
#if	linux && __amd64__
				gen_rtx_LT(VOIDmode, flags_reg_ea, const0_rtx),
#elif	linux && __i386__
				gen_rtx_GEU(VOIDmode, flags_reg_ea, const0_rtx),
#else
	#error  "[!] Unsupported platform"	/* unknown platform */
#endif
				/* 
				 * goto branch_chk_lbl if the memory location
				 * that stores the branch address >= kernel base
				 */
				gen_rtx_LABEL_REF(VOIDmode, branch_chk_lbl),
				pc_rtx)),
				cmp_ea);

	/* link the jump instruction with the violation label */
	JUMP_LABEL(jmp_ea) = branch_chk_lbl;
	LABEL_NUSES(branch_chk_lbl)++;
	
	/* 
	 * generate a "pop" instruction; remove the EA of
	 * the branch target from the stack
	 */
	pop		= emit_insn_after(gen_rtx_pop(copy_rtx(btarget_ea)),
				jmp_ea);
	
	/* generate a "call" instruction; invoke the violation handler */
	(void)emit_call_insn_after(gen_rtx_CALL(VOIDmode,
				gen_rtx_MEM(QImode, copy_rtx(vsaddr)),
				const0_rtx),
				pop);
	/* 
	 * generate a "pop" instruction; remove the EA of
	 * the branch target from the stack
	 */
	pop_fix		= emit_insn_after(gen_rtx_pop(copy_rtx(btarget_ea)),
				branch_chk_lbl);

	/* generate a compare instruction */
	cmp		= emit_insn_after(gen_rtx_SET(VOIDmode, flags_reg,
				gen_rtx_COMPARE(cmpmode, btarget, ksaddr)),
				pop_fix);
	
	/* generate a jump instruction */
	jmp		= emit_jump_insn_after(gen_rtx_SET(VOIDmode,
				/* rtx expression for the PC */
				pc_rtx,
				gen_rtx_IF_THEN_ELSE(VOIDmode,
#if	linux && __amd64__
				gen_rtx_LT(VOIDmode, flags_reg, const0_rtx),
#elif	linux && __i386__
				gen_rtx_GEU(VOIDmode, flags_reg, const0_rtx),
#else
	#error  "[!] Unsupported platform"	/* unknown platform */
#endif
				/* 
				 * goto the branch instruction if target branch
				 * address >= kernel base
				 */
				gen_rtx_LABEL_REF(VOIDmode, branch_lbl),
				pc_rtx)),
				cmp);
	
	/* link the jump instruction with the branch label */
	JUMP_LABEL(jmp)	=  branch_lbl;
	LABEL_NUSES(branch_lbl)++;
	
	/* generate the "fix" code */
	(void)emit_insn_after(gen_rtx_SET(VOIDmode,
			copy_rtx(btarget),
			vsaddr),
			jmp);
}

/*
 * check if the target address of an indirect branch is *stored*
 * into a "safe" memory location:
 * 	i.	a fixed memory location (e.g., obtained via a symbol name).
 * 	ii.	a memory location that is obtained via a fixed memory address
 * 		(see case i. above), along with some constant arithmetic
 * 		operation (i.e., +/- a constant number of bytes).
 *
 * ea:		the effective address to analyze
 *
 * returns:	SUCC if the ea is stored into one of the
 * 		aforementioned locations, FAIL otherwise  
 */
static int
safe_ea(const rtx ea)
{
	/* cases i, ii */
	if (GET_RTX_CLASS(GET_CODE(ea)) == RTX_CONST_OBJ)
		return SUCC;
	else
		return FAIL;
}

/* 
 * jump_insn expression handler
 *
 * Inspect the sub-expressions of a jump_insn instruction
 * (i.e., the PATTERN) and search for indirect jumps or returns;
 * whenever one is found, call the appropriate instrumentation function.
 *
 * jump_insn:	the jump_insn expression
 * htab:	the hash table with the instrumented instructions
 */
static void
handle_jump_insn(const rtx jump_insn, const htab_t htab)
{
	rtx jump;	/* indirect jump sub-expression (ptr) */
	rtx taddr;	/* sub-expression with the branch target; address */

	/* check if we have already handled this jump_insn instruction */
	if (unlikely(htab_find(htab, jump_insn) != NULL))
		/* already handled; return */
		return;
	
	/*  check all the sub-expressions of jump_insn for indirect jumps */
	if (likely((jump = contains_indirect_jump(PATTERN(jump_insn))) == NULL))
	{
#ifdef	DEBUG /* auditing */
		commitlog(jump_insn, NO_INSTR);
#endif /* DEBUG */

		/* no indirect jumps found; return */
		return;
	}

	/* jump vs return/eh_return */
	if ((GET_CODE(jump) == EH_RETURN)		||
#if	GCCPLUGIN_VERSION >= 4007
		/* GCC 4.7.x series have more than one `return' expression */
		(GET_CODE(jump) == SIMPLE_RETURN)	||
#endif
		(GET_CODE(jump) == RETURN)) {
		/* return/eh_return */
		instr_branch_safe(jump_insn, NULL, GET_CODE(jump));

#ifdef	DEBUG /* auditing */
		commitlog(jump_insn, SAFE_RET_INSTR);
#endif /* DEBUG */
	
	}
	else {	/* indirect jump */
		/* extract the branch target */
		taddr = XEXP(jump, 1);

		/* 
		 * indirect jump via a register (e.g., jmp *%eax; ea = %eax),
		 * or via a safe memory location; (see the comments of safe_ea()
		 * for more info about safe EA locations)
		 */
		if (unlikely(REG_P(taddr))) {
			instr_branch_safe(jump_insn, jump, JUMP_INSN);

#ifdef	DEBUG /* auditing */
			commitlog(jump_insn, SAFE_R_INSTR);
#endif /* DEBUG */
		}
		else if (unlikely(safe_ea(XEXP(taddr, 0)) == SUCC)) {
			instr_branch_safe(jump_insn, jump, JUMP_INSN);

#ifdef	DEBUG /* auditing */
			commitlog(jump_insn, SAFE_M_INSTR);
#endif /* DEBUG */
		}
		else {
			/* 
			 * indirect jump via an unsafe memory location
			 * (e.g., jmp *(%eax)); ea = (%eax)
			 */
			instr_branch_unsafe(jump_insn, jump, 
					XEXP(taddr, 0), JUMP_INSN);

#ifdef	DEBUG /* auditing */
			commitlog(jump_insn, UNSAFE_INSTR);
#endif /* DEBUG */
		}
	}

	/* insert the instruction (jump_insn) into the handled set */
	*htab_find_slot(htab, jump_insn, INSERT) = jump_insn;
}

/* 
 * call_insn expression handler
 *
 * Inspect the sub-expressions of a call_insn instruction
 * (i.e., the PATTERN) and search for indirect calls; whenever
 * one is found, call the appropriate instrumentation function.
 *
 * call_insn:	the call_insn expression
 * htab:	the hash table with the instrumented instructions
 */
static void
handle_call_insn(const rtx call_insn, const htab_t htab)
{
	rtx call;	/* indirect call sub-expression (ptr) */
	rtx taddr;	/* sub-expression with the branch target; address */

	/* check if we have already handled this call_insn instruction */
	if (unlikely(htab_find(htab, call_insn) != NULL))
		/* already handled; return */
		return;
	
	/*  check all the sub-expressions of call_insn for indirect calls */
	if (likely((call = contains_indirect_call(PATTERN(call_insn))) == NULL))
	{
#ifdef	DEBUG /* auditing */
		commitlog(call_insn, NO_INSTR);
#endif /* DEBUG */

		/* no indirect calls found; return */
		return;
	}

	/* extract the branch target */
	taddr = XEXP(XEXP(call, 0), 0);

	/* 
	 * indirect call via a register (e.g., call *%eax; ea = %eax),
	 * or via a safe memory location; (see the comments of safe_ea()
	 * for more info about safe EA locations)
	 */
	if (unlikely(REG_P(taddr))) {
		instr_branch_safe(call_insn, call, CALL_INSN);
	
#ifdef	DEBUG /* auditing */
		commitlog(call_insn, SAFE_R_INSTR);
#endif /* DEBUG */
	}
	else if (unlikely(safe_ea(XEXP(taddr, 0)) == SUCC)) {
		instr_branch_safe(call_insn, call, CALL_INSN);

#ifdef	DEBUG /* auditing */
		commitlog(call_insn, SAFE_M_INSTR);
#endif /* DEBUG */
	}
	else {
		/* 
		 * indirect call via an unsafe memory location
		 * (e.g., call *(%eax)); ea = (%eax)
		 */
		instr_branch_unsafe(call_insn, call, XEXP(taddr, 0), CALL_INSN);

#ifdef	DEBUG /* auditing */
		commitlog(call_insn, UNSAFE_INSTR);
#endif /* DEBUG */
	}

	/* insert the instruction (call_insn) into the handled set */
	*htab_find_slot(htab, call_insn, INSERT) = call_insn;
}

/* 
 * branch-prot pass
 * (callback; invoked for every translation unit) 
 *
 * Confine all indirect branches via instrumentation;
 * computed branches are *sandboxed* by disallowing
 * targets outside the kernel code segment.
 *
 * NOTE: It may terminate the compilation process
 * if it runs out of memory.
 *
 * returns: SUCC on success, FAIL on error
 */
unsigned int __attribute__ ((visibility("default")))
branchprot_instrument(void)
{
	/* iterators */
	basic_block it_bb;	/* basic block (BB) iterator */
	rtx it_insn;		/* instruction (INSN) iterator */

	/* hash table with the instructions to be instrumented */
	htab_t htab_insn;

	/* 
	 * allocate a new hash table; it may call exit(3) if xcalloc()
	 * runs out of memory. The hash table implementation is the
	 * typical GCC htab_t
	 *
	 * NOTE: There is no need to check the return value for NULL,
	 * xcalloc() will handle this
	 */
	htab_insn = htab_create_alloc(HTAB_SZ_DFL,
			htab_hash_pointer,	/* ptr to INSN */
			htab_eq_pointer,
			NULL,
			xcalloc,		/* xcalloc allocator */
			free);			/* std free(3) */
	
#ifdef	DEBUG /* auditing */
	openlog();
#endif /* DEBUG */

	/* traverse all the basic blocks of the translation unit */
	FOR_EACH_BB(it_bb)
		/* traverse all the instructions in the basic block */
		FOR_BB_INSNS(it_bb, it_insn)
			/* invoke the appropriate handler */
			switch (GET_CODE(it_insn)) {
				/* call_insn instructions */
				case CALL_INSN:
					handle_call_insn(it_insn, htab_insn);
					break;
				/* jump_insn instructions */
				case JUMP_INSN:
					handle_jump_insn(it_insn, htab_insn);
					break;
				default:
					/* make the compiler happy */
					break;
			}

#ifdef	DEBUG /* auditing */
	closelog();
#endif /* DEBUG */

	/* cleanup; deallocate the hash table */
	free(htab_insn);

	/* return with success */
	return SUCC;
}

/*
 * argument parsing
 *
 * Parse the plugin arguments and set the corresponding
 * variables (i.e., `stub', `nop', `log', `retprot').
 *
 * plugin_info:	information regarding the plugin; provided by GCC
 *
 * returns: SUCC on success, FAIL on error
 */
static int
parse_args(const struct plugin_name_args *plugin_info)
{
	/* iterator */
	int i;

	/* argument length */
	size_t len;

	/* parse the plugin arguments (if any) */
	for (i = 0; i < plugin_info->argc; i++) {

		/* where is my getopt-like API? */
		
		/* get the length of the argument */
		len = strlen(plugin_info->argv[i].key);
		
		/* stub */
		if (strncmp(plugin_info->argv[i].key,
					STUB_STR,
					strlen(STUB_STR)) == 0 &&
				len == strlen(STUB_STR)) {
			if ((plugin_info->argv[i].value != NULL) &&
				(strlen(plugin_info->argv[i].value) != 0))
				/* stub can be an address or a symbol name */
				stub = plugin_info->argv[i].value;
			else {
				/* missing stub */
				(void)fprintf(stderr,
					"%s: missing option for argument %s\n",
					NAME,
					plugin_info->argv[i].key);

				/* fail */
				return FAIL;
			}
		}
		/* nop */
		else if (strncmp(plugin_info->argv[i].key,
					NOP_STR,
					strlen(NOP_STR)) == 0 &&
				len == strlen(NOP_STR)) {
			if ((plugin_info->argv[i].value != NULL) &&
				(strlen(plugin_info->argv[i].value) != 0))
				/* parse the decimal option */
				nop = strtoul(plugin_info->argv[i].value,
						NULL,
						BASE10);
			else {
				/* missing nop */
				(void)fprintf(stderr,
					"%s: missing option for argument %s\n",
					NAME,
					plugin_info->argv[i].key);

				/* fail */
				return FAIL;
			}
		}
#ifdef	DEBUG
		/* log */
		else if (strncmp(plugin_info->argv[i].key,
					LOG_STR,
					strlen(LOG_STR)) == 0 &&
				len == strlen(LOG_STR)) {
			if ((plugin_info->argv[i].value != NULL) &&
				(strlen(plugin_info->argv[i].value) != 0))
				/* set the log filename */
				log = plugin_info->argv[i].value;
			else {
				/* missing log filename */
				(void)fprintf(stderr,
					"%s: missing option for argument %s\n",
					NAME,
					plugin_info->argv[i].key);

				/* fail */
				return FAIL;
			}
		}
#endif
		/* retprot */
		else if (strncmp(plugin_info->argv[i].key,
					RETPROT_STR,
					strlen(RETPROT_STR)) == 0 &&
				len == strlen(RETPROT_STR)) {
			if ((plugin_info->argv[i].value != NULL) &&
				(strlen(plugin_info->argv[i].value) != 0)) {
				/* set the retprot flag */
				if ((retprot =
					strtol(plugin_info->argv[i].value,
						NULL,
						BASE10)) > 0)
					retprot = 1;
			}
			else {
				/* missing log filename */
				(void)fprintf(stderr,
					"%s: missing option for argument %s\n",
					NAME,
					plugin_info->argv[i].key);

				/* fail */
				return FAIL;
			}
		}
		/* default handler */
		else {
			/* invalid argument */
			(void)fprintf(stderr,
				"%s: invalid argument %s\n",
				NAME,
				plugin_info->argv[i].key);

			/* fail */
			return FAIL;
		}
	}

	/* success */
	return SUCC;
}

/*
 * version checking
 *
 * Parse and compare two GCC versions.
 *
 * NOTE:
 * 	- The two versions are assumed to be in
 * 	the form: "MAJOR.MINOR.PATCHLEVEL", and
 * 	{MAJOR, MINOR, PATCHLEVEL} < 10.
 * 	- We invoke `strtol()' without checking
 * 	`errno' for `ERANGE'.
 *
 * lhs_ver:	the first version to compare
 * rhs_ver:	the second version to compare
 *
 * returns:	0 if the two versions are the same,
 * 		>0 if lhs_ver > rhs_ver, or <0 otherwise
 */
static int
version_check(const struct plugin_gcc_version *lhs_ver,
		const struct plugin_gcc_version *rhs_ver)
{
	/* iterator */
	const char *it	= NULL;
	
	/* base multiplier */
	size_t mult	= 1;

	/* parsed versions; integers */
	size_t lhsver	= 0;
	size_t rhsver	= 0;

	/* parse the lhs_ver version */

	/* "it" points to the end of the version string */
	it = lhs_ver->basever + strlen(lhs_ver->basever) -
		((strlen(lhs_ver->basever) > 0) ? 1 : 0);

	/* right-to-left traversal */
	while(lhs_ver->basever != it--) {
		/* found delimiter */
		if (*it == VER_DELIM) {
			/* extract the subversion */
			lhsver	+= (mult * strtol(it + 1, NULL, BASE10));
			/* update the multiplier (i.e., base) */
			mult	*= BASE10;
		}
	}
	/* extract the remainder */
	lhsver += (mult * strtol(lhs_ver->basever, NULL, BASE10));

	/* fix (e.g., 4.6 needs to be 460 and not 46) */
	while (unlikely((lhsver < BASE100) && (lhsver > 0))) lhsver *= BASE10;
	while (unlikely(lhsver > (10 * BASE100) - 1)) lhsver /= BASE10;
	
	/* parse the rhs_ver version */

	/* reset the multiplier */
	mult = 1;

	/* same as lhs_ver */
	it = rhs_ver->basever + strlen(rhs_ver->basever) -
		((strlen(rhs_ver->basever) > 0) ? 1 : 0);
	while(rhs_ver->basever != it--) {
		if (*it == VER_DELIM) {
			rhsver	+= (mult * strtol(it + 1, NULL, BASE10));
			mult	*= BASE10;
		}
	}
	rhsver += (mult * strtol(rhs_ver->basever, NULL, BASE10));
	
	while (unlikely((rhsver < BASE100) && (rhsver > 0))) rhsver *= BASE10;
	while (unlikely(rhsver > (10 * BASE100) - 1)) rhsver *= BASE10;
	
	/* return the difference of lhs_ver and rhs_ver */
	return lhsver - rhsver;	
}

/*
 * plugin initialization (kGuard)
 *
 * Invoked right after the plugin is loaded. It does some version
 * checking and registers the `branch-prot' RTL pass that performs
 * code instrumentation.
 *
 * NOTE: The new pass (i.e., `branch-prot') is invoked after most
 * of the low-level optimizations have been applied, since we do
 * not want to instrument code that will be modified or removed
 * due to subsequent optimization passes.
 *
 * plugin_info:	information regarding the plugin; provided by GCC
 * version:	version information; provided by GCC
 *
 * returns:	SUCC on success, FAIL on error
 */
int __attribute__ ((visibility("default")))
plugin_init(struct plugin_name_args *plugin_info,
		struct plugin_gcc_version *version)
{
	/* pass control structure */
	struct register_pass_info pass_info;

	/* version checking; the actual GCC version vs. required GCC */
	if (unlikely(version_check(version, &pver) < 0)) {
		/* incompatible GCC version */
		(void)fprintf(stderr,
			"%s: incompatible GCC version: %s (required >= %s)\n",
			NAME,
			version->basever,
			pver.basever);

		/* failed */
		goto err;
	}

	/* GCC 4.5.x series need compatibility mode */
	if (strncmp(version->basever, GCC45_PREF, strlen(GCC45_PREF)) == 0)
		compat = 1;

	/* argument parsing */
	if (unlikely(parse_args(plugin_info) == FAIL))
		/* failed */
		goto err;

	/* provide version and help information to GCC */
	register_callback(plugin_info->base_name, PLUGIN_INFO, NULL, &pinfo);

	/* register the new pass; std boilerplate */
	pass_info.pass 				= &pass_branchprot.pass;
	pass_info.ref_pass_instance_number	= 0;
	pass_info.pos_op			= PASS_POS_INSERT_AFTER;

	/* chain the new pass after "vartrack"; why?... good question */
	pass_info.reference_pass_name		= "vartrack";
	pass_info.pass->next			=
					pass_variable_tracking.pass.next;
	
	/* provide the pass information to the pass manager */
	register_callback(plugin_info->base_name,
				PLUGIN_PASS_MANAGER_SETUP,
				NULL,
				&pass_info);

	/* exit with success */
	return SUCC;

err:
	/* exit with failure */
	return FAIL;
}
