/*
    MIT License

    Copyright (c) 2022 David Reguera Garcia aka Dreg

    dreg@fr33project.org
    https://fr33project.org/
    https://github.com/therealdreg
    @therealdreg

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

    WARNING: bullshit POC code, the crappiest crap
*/

#define BED_VER "0.1alpha"

#include <assert.h>

#include "bochs.h"
#include "cpu/cpu.h"

void bx_instr_init_env(void) {}
void bx_instr_exit_env(void) {}
void bx_instr_reset(unsigned cpu, unsigned type) {}
void bx_instr_before_execution(unsigned cpu, bxInstruction_c* bx_instr) {}
void bx_instr_after_execution(unsigned cpu, bxInstruction_c* bx_instr) {}
void bx_instr_cnear_branch_taken(unsigned cpu, bx_address branch_eip, bx_address new_eip) {}
void bx_instr_cnear_branch_not_taken(unsigned cpu, bx_address branch_eip) {}
void bx_instr_ucnear_branch(unsigned cpu, unsigned what, bx_address branch_eip, bx_address new_eip) {}
void bx_instr_far_branch(unsigned cpu, unsigned what, Bit16u prev_cs, bx_address prev_eip, Bit16u new_cs, bx_address new_eip) {}
void bx_instr_interrupt(unsigned cpu, unsigned vector) {}
void bx_instr_exception(unsigned cpu, unsigned vector, unsigned error_code) {}
void bx_instr_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs, bx_address eip) {}
void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_phy_address phy, unsigned len, unsigned memtype, unsigned rw) {}

struct val_name_tbl
{
    const unsigned int val;
    const char* name;
};

void phelp(void);
void procmd(char* cmd);
void reopenf(void);
char* resym(Bit64u addr);
bool is_str(unsigned char* str);
bool convert_to_str(unsigned char* str);
void printderef(Bit64u eaddr, unsigned int deep);
void cleanfile(void);
Bit64u mydis(Bit64u from, int numlines);
void printctx(void);
void reff(bx_address addr, unsigned int nr_col, unsigned int deep);
void myctx(void);
bool laddr_to_physaddr(bx_lin_address laddr, bx_phy_address* out);
void lowerstr(unsigned char* str);
unsigned int myhd(unsigned int addr_c, unsigned int lines);

void bx_instr_initialize(unsigned cpu)
{
    reopenf();
    phelp();
}

void bx_instr_debug_promt()
{
    myctx();
}

void bx_instr_debug_cmd(const char* cmd)
{
    unsigned char* mem = (unsigned char*)calloc(1, strlen(cmd) + 2);

    if (NULL == mem)
    {
        return;
    }
    strcpy((char*)mem, cmd);
    lowerstr(mem);
    cleanfile();

    procmd((char*)mem);

    free(mem);
}

#define EFL_CF 0x00000001   /* carry */
#define EFL_PF 0x00000004   /* parity of low 8 bits */
#define EFL_AF 0x00000010   /* carry out of bit 3 */
#define EFL_ZF 0x00000040   /* zero */
#define EFL_SF 0x00000080   /* sign */
#define EFL_TF 0x00000100   /* trace trap */
#define EFL_IF 0x00000200   /* interrupt enable */
#define EFL_DF 0x00000400   /* direction */
#define EFL_OF 0x00000800   /* overflow */
#define EFL_IOPL 0x00003000 /* IO privilege level: */
#define EFL_NT 0x00004000   /* nested task */
#define EFL_RF 0x00010000   /* resume without tracing */
#define EFL_VM 0x00020000   /* virtual 8086 mode */
#define EFL_AC 0x00040000   /* alignment check */
#define EFL_VIF 0x00080000  /* virtual interrupt flag */
#define EFL_VIP 0x00100000  /* virtual interrupt pending */
#define EFL_ID 0x00200000   /* cpuID instruction */

struct val_name_tbl efl_name_val_tbl[]
{
    {EFL_CF, "cf"},
        {EFL_PF, "pf"},
        {EFL_AF, "af"},
        {EFL_ZF, "zf"},
        {EFL_SF, "sf"},
        {EFL_TF, "tf"},
        {EFL_IF, "if"},
        {EFL_DF, "df"},
        {EFL_OF, "of"},
        {EFL_IOPL, "iopl"},
        {EFL_NT, "nt"},
        {EFL_RF, "rf"},
        {EFL_VM, "vm"},
        {EFL_AC, "ac"},
        {EFL_VIF, "vif"},
        {EFL_VIP, "vip"},
        {EFL_ID, "id"},
};

bool enstack = true;

bool enasm = true;

bool enregs = true;

unsigned int watchaddr;

unsigned int watchlines = 10;

FILE* ctx;

void phelp(void)
{
    fprintf(stderr,
    "\n"
    "bochs-bed (crap POC) " BED_VER " David Reguera Garcia aka Dreg\n"
    "\n"
    "dreg@fr33project.org\n"
    "https://fr33project.org/\n"
    "https://github.com/therealdreg\n"
    "\n"
    "help: instrument phelp\n"
    "show context: instrument ctx\n"
    "hexdump: instrument hexdump<0xADDR> Ex: instrument hexdump0xF737CAE4\n"
    "hexdump next chunk: instrument hexdump\n"
    "patch memory: instrument patchb<0xADDR>_<0xBYTE1_0xBYTE2...> Ex: instrument patchb0xF737CAE4_0x69_0x68_0x67_0x66\n"
    "set/unset flags: instrument setf<1|0Flag...> Ex: (ID = 1, IOPL = 0, TF = 1) instrument setf1id0iopl1tf\n"
    "disassemble: instrument dis<0xADDR> Ex: instrument dis0x80537F58\n"
    "disassemble next chunk: instrument disassemble\n"
    "watch memory: instrument watch<0xADDR>[_0xNR-LINES] Ex: instrument watch0x80537F58_0x3\n"
    "remove watch memory: instrument watch0\n"
    "dereference/telescope: instrument tel<0xADDR><n0xNR-COLS><_0xDEPTH> Ex: instrument tel0xF737CAE8n0x3_0x5\n"
    "remove layout: instrument layout\n"
    "add layout: instrument layout<asm|stack|regs> Ex: instrument layoutstackasmregs\n"
    "convert address to symbol: instrument hexdump<0xADDR>\n"
    "\n"
    );
}

unsigned int myhd(unsigned int addr_c, unsigned int lines)
{
    unsigned char buff[16] = { 0 };

    for (unsigned int j = 0; j < lines; j++)
    {
        if (bx_dbg_read_linear(dbg_cpu, (bx_address)addr_c, 16, (Bit8u*)buff))
        {
            fprintf(stderr, "0x%08X ", addr_c);
            for (int i = 0; i < 16; i++)
            {
                fprintf(stderr, "%02X ", buff[i]);
            }
            fprintf(stderr, "   ");
            for (int i = 0; i < 16; i++)
            {
                if (buff[i] >= 0x20 && buff[i] <= 0x7E)
                {
                    fprintf(stderr, "%c", buff[i]);
                }
                else
                {
                    fprintf(stderr, ".");
                }
            }
            fprintf(stderr, " ; %.25s\n", resym(addr_c));
        }
        addr_c += 16;
    }

    return addr_c;
}

void procmd(char* cmd)
{
    unsigned char* mem = (unsigned char*)cmd;

    if (strcmp(cmd, "ctx") == 0)
    {
        myctx();
    }
    else if (strncmp(cmd, "phelp", strlen("phelp")) == 0)
    {
        phelp();
    }
    else if (strncmp(cmd, "layout", strlen("layout")) == 0)
    {
        enstack = false;
        enasm = false;
        enregs = false;
        watchaddr = false;

        if (strstr(cmd, "regs"))
        {
            enregs = true;
        }
        if (strstr(cmd, "asm"))
        {
            enasm = true;
        }
        if (strstr(cmd, "stack"))
        {
            enstack = true;
        }
    }
    else if (strncmp(cmd, "tel", strlen("tel")) == 0)
    {
        unsigned int addr_c = 0;
        unsigned int cols = 0;
        unsigned int deep = 0;

        char* addr;
        char* colls;

        addr = (char*)strstr((char*)mem, "0x");
        if (NULL != addr)
        {
            unsigned int addr_c = 0;
            colls = (char*)strstr((char*)mem, "n0x");
            if (NULL != colls)
            {
                *colls = '\0';
                addr_c = (unsigned int)strtoll(addr, NULL, 16);
                *colls = 'n';

                cols = (unsigned int)strtoll(colls + 1, NULL, 16);
                addr = (char*)strstr((char*)mem, "_0x");
                if (NULL != addr)
                {
                    deep = (unsigned int)strtoll(addr + 1, NULL, 16);
                    fprintf(stderr, "addr_c 0x%08X cols 0x%08X deep 0x%08X\n", addr_c, cols, deep);
                    reff((bx_address)addr_c, cols, deep);
                    printctx();
                }
            }
        }
    }
    else if (strncmp(cmd, "dis", strlen("dis")) == 0)
    {
        char* addr;
        static unsigned last_addr;

        addr = (char*)strstr((char*)mem, "0x");
        if (NULL != addr)
        {
            unsigned int addr_c = 0;
            addr_c = (unsigned int)strtoll(addr, NULL, 16);
            last_addr = addr_c;
        }

        last_addr = (unsigned int)mydis(last_addr, 25);
        printctx();
        fprintf(stderr, "to show the next chunk type: instrument dis\n");
    }
    else if (strncmp(cmd, "setf", strlen("setf")) == 0)
    {
        unsigned int reg = (unsigned int)BX_CPU(dbg_cpu)->read_eflags();

        for (int i = 0; i < sizeof(efl_name_val_tbl) / sizeof(*efl_name_val_tbl); i++)
        {
            char* curr;
            curr = strstr((char*)mem + 4, efl_name_val_tbl[i].name);
            if (NULL != curr)
            {
                if (*(curr - 1) == '1')
                {
                    reg |= efl_name_val_tbl[i].val;
                }
                else if (*(curr - 1) == '0')
                {
                    reg &= ~efl_name_val_tbl[i].val;
                }
            }
        }
        BX_CPU(dbg_cpu)->setEFlags(reg);

        bx_dbg_info_flags();
    }
    else if (strncmp(cmd, "patchb", strlen("patchb")) == 0)
    {
        char* addr = NULL;
        unsigned int orig_addr_c = 0;
        int i = 0;

        addr = (char*)strstr((char*)mem, "0x");
        if (NULL != addr)
        {
            unsigned int addr_c = 0;
            addr_c = (unsigned int)strtoll(addr, NULL, 16);
            orig_addr_c = addr_c;

            fprintf(stderr, "patchb: 0x%08X %s\n", addr_c, resym(addr_c));
            unsigned char* cb;
            unsigned char* nextcb;
            do
            {
                nextcb = NULL;
                cb = (unsigned char*)strstr(addr, "_0x");
                if (NULL != cb)
                {
                    nextcb = (unsigned char*)strstr((char*)cb + 1, "_0x");
                    if (NULL != nextcb)
                    {
                        *nextcb = '\0';
                    }
                    mem[i++] = (unsigned char)strtol((char*)cb + 1, NULL, 16);
                    if (NULL != nextcb)
                    {
                        *nextcb = '_';
                    }
                }
                addr = (char*)nextcb;
            } while (NULL != addr);

            bx_phy_address physadd;
            for (int j = 0; j < i; j++)
            {
                if (laddr_to_physaddr(addr_c, &physadd))
                {
                    bx_dbg_setpmem_command(physadd, 1, mem[j]);
                }
                addr_c++;
            }
            fprintf(stderr, "patched! check it with: instrument hexdump0x%08X\n", orig_addr_c);
        }
    }
    else if (strncmp(cmd, "watch", strlen("watch")) == 0)
    {
        char* addr = NULL;
        addr = (char*)strstr((char*)mem, "0x");
        if (NULL != addr)
        {
            watchaddr = (unsigned int)strtoll(addr, NULL, 16);
            fprintf(stderr, "watching: 0x%08X\n", watchaddr);
            addr = (char*)strstr((char*)mem, "_0x");
            if (NULL != addr)
            {
                watchlines = (unsigned int)strtoll(addr + 1, NULL, 16);
            }
            else
            {
                watchlines = 10;
            }
        }
        else
        {
            watchaddr = 0;
        }
    }
    else if (strncmp(cmd, "hexdump", strlen("hexdump")) == 0)
    {
        static unsigned int last_addr;
        char* addr = NULL;
        unsigned int addr_c = 0;

        addr = (char*)strstr((char*)mem, "0x");
        if (NULL != addr)
        {
            addr_c = (unsigned int)strtoll(addr, NULL, 16);
        }
        else
        {
            addr_c = last_addr;
        }
        if (addr_c != 0)
        {
            fprintf(stderr, "hexdump: 0x%08X %s\n", addr_c, resym(addr_c));
            last_addr = myhd(addr_c, 16);
            fprintf(stderr, "To show next chunk just type: instrument hexdump\n");
            fprintf(stderr, "Try to patch this memory area with: instrument patchb0x%08X_0x69_0x68_0x67_0x66\n", addr_c);
        }
    }
    else
    {
        fprintf(stderr, "wrong command, wtf\n");
    }
}

void reopenf(void)
{
    if (NULL != ctx)
    {
        fclose(ctx);
    }

    ctx = fopen("lastctx.log", "wb+");
    if (NULL == ctx)
    {
        fprintf(stderr, "error, cant open lastctx.log, please fix it!\n");
    }
}

char* resym(Bit64u addr)
{
    char* sym = (char*)bx_dbg_symbolic_address(BX_CPU(dbg_cpu)->cr3 >> 12, (bx_address)addr, BX_CPU(dbg_cpu)->get_segment_base(BX_SEG_REG_CS));
    if (strcmp(sym, "unk. ctxt") == 0 || strcmp(sym, "no symbol") == 0)
    {
        return " ";
    }

    return sym;
}

bool is_str(unsigned char* str)
{
    if (*str == '\0')
    {
        return false;
    }

    while (*str != '\0')
    {
        if (*str < 0x20)
        {
            return false;
        }
        else if (*str > 0x7E)
        {
            return false;
        }

        str++;
    }

    return true;
}

bool convert_to_str(unsigned char* str)
{
    unsigned char* new_str = str;
    unsigned int i = 0;

    if (*str == '\0')
    {
        return false;
    }

    while (*str != '\0')
    {
        if (str[1] != '\0')
        {
            return false;
        }

        if (*str < 0x20)
        {
            return false;
        }
        else if (*str > 0x7E)
        {
            return false;
        }

        new_str[i++] = *str;

        str += 2;
    }

    new_str[i] = '\0';

    return true;
}

void printderef(Bit64u eaddr, unsigned int deep)
{
    unsigned int addr = (unsigned int)eaddr;
    unsigned int curr = 0;
    unsigned int last = 0;
    unsigned char str[16] = { 0 };
    last = addr;
    bool failstr;

    for (unsigned int i = 0; i < deep; i++)
    {
        curr = 0;
        if (bx_dbg_read_linear(dbg_cpu, (bx_address)addr, 4, (Bit8u*)&curr))
        {
            if (addr == curr)
            {
                fprintf(ctx, " -> loop <- ");
                return;
            }
            fprintf(ctx, " -> 0x%08X %.10s", curr, resym(curr));
        }
        else
        {
            memset(str, 0, sizeof(str));
            if (bx_dbg_read_linear(dbg_cpu, (bx_address)last, sizeof(str) - 2, (Bit8u*)str))
            {
                failstr = true;
                if (is_str(str))
                {
                    if (strlen((const char*)str) > 3)
                    {
                        failstr = false;
                        fprintf(ctx, "= '%.10s'", str);
                    }
                }
                if (failstr)
                {
                    if (convert_to_str(str))
                    {
                        if (strlen((const char*)str) > 3)
                        {
                            fprintf(ctx, "= u'%.10s'", str);
                        }
                    }
                }
            }
            return;
        }
        last = addr;
        addr = curr;
    }
}

void cleanfile(void)
{
    reopenf();
}

Bit64u mydis(Bit64u from, int numlines)
{
    static Bit8u bx_disasm_ibuf[32];
    static char bx_disasm_tbuf[512];
    Bit64u last_frm = from;

    Bit64u to = from + (16 * 20);

    unsigned dis_size = 16; // until otherwise proven
    if (BX_CPU(dbg_cpu)->sregs[BX_SEG_REG_CS].cache.u.segment.d_b)
        dis_size = 32;
    if (BX_CPU(dbg_cpu)->get_cpu_mode() == BX_MODE_LONG_64)
        dis_size = 64;
    char* Sym = NULL;
    do
    {
        numlines--;

        if (!bx_dbg_read_linear(dbg_cpu, from, 16, bx_disasm_ibuf))
            break;

        unsigned ilen = bx_dbg_disasm_wrapper(dis_size == 32, dis_size == 64,
            0 /*(bx_address)(-1)*/, from /*(bx_address)(-1)*/, bx_disasm_ibuf, bx_disasm_tbuf);

        Sym = resym(from);
        last_frm = from;
        fprintf(ctx, "0x%08X: ", (unsigned int)from);
        fprintf(ctx, "(%20s): ", Sym ? Sym : "");
        fprintf(ctx, "%-25s ; ", bx_disasm_tbuf);

        for (unsigned j = 0; j < ilen; j++)
            fprintf(ctx, "%02x", (unsigned)bx_disasm_ibuf[j]);
        fprintf(ctx, "\n");

        from += ilen;
    } while ((from < to) && numlines > 0);

    return last_frm;
}

void printctx(void)
{
    size_t bytesRead = 0;
    static unsigned char buff[512];

    fprintf(stderr, "\n");

    fseek(ctx, 0L, SEEK_SET);
    while ((bytesRead = fread(buff, 1, sizeof(buff), ctx)) > 0)
    {
        fwrite(buff, 1, bytesRead, stderr);
    }
    cleanfile();
}

void reff(bx_address addr, unsigned int nr_col, unsigned int deep)
{
    unsigned int curr;
    for (unsigned int i = 0; i < nr_col; i++)
    {
        curr = 0;
        bx_dbg_read_linear(dbg_cpu, (bx_address)addr, 4, (Bit8u*)&curr);
        fprintf(ctx, "[+%3Xh] 0x%08X 0x%08x %s", i * 4, (unsigned int)addr, curr, resym(curr));
        printderef(curr, deep);
        fprintf(ctx, "\n");
        addr += 4;
    }
}

void myctx(void)
{
    struct val_name_tbl regtb[]
    {
        {BX_64BIT_REG_RAX, "eax"},
            {BX_64BIT_REG_RBX, "ebx"},
            {BX_64BIT_REG_RCX, "ecx"},
            {BX_64BIT_REG_RDX, "edx"},
            {BX_64BIT_REG_RSI, "esi"},
            {BX_64BIT_REG_RDI, "edi"},
            {BX_64BIT_REG_RSP, "esp"},
            {BX_64BIT_REG_RBP, "ebp"},
            {BX_64BIT_REG_RIP, "eip"},
    };
    unsigned int reg = 0;
    unsigned int rsp = 0;

    cleanfile();

    if (enregs)
    {
        for (int i = 0; i < sizeof(regtb) / sizeof(*regtb); i++)
        {
            reg = (unsigned int)BX_CPU(dbg_cpu)->gen_reg[regtb[i].val].dword.erx;

            fprintf(ctx, "%s: 0x%08X %s", regtb[i].name, reg, resym(reg));
            if (regtb[i].val != BX_64BIT_REG_RIP)
            {
                printderef(reg, 4);
            }
            fprintf(ctx, "\n");
        }
        fprintf(ctx, "eflags: 0x%08x\n", (unsigned)BX_CPU(dbg_cpu)->read_eflags());
    }

    if (enasm)
        mydis(bx_dbg_get_eip(), 15);
    if (enstack)
        reff((bx_address)(unsigned int)BX_CPU(dbg_cpu)->gen_reg[BX_64BIT_REG_RSP].dword.erx, 12, 4);

    printctx();
    if (enregs)
        bx_dbg_info_flags();

    if (watchaddr)
    {
        myhd(watchaddr, watchlines);
    }
}

bool laddr_to_physaddr(bx_lin_address laddr, bx_phy_address* out)
{
    bx_phy_address paddr;
    bx_address lpf_mask;
    bx_lin_address orig = laddr;

    laddr &= BX_CONST64(0xfffffffffffff000);

    bool paddr_valid = BX_CPU(dbg_cpu)->dbg_xlate_linear2phy(laddr, &paddr, &lpf_mask, 1);
    if (paddr_valid)
    {
        *out = paddr | (orig & 0x0000000000000FFF);
        dbg_printf("linear page 0x" FMT_ADDRX " maps to physical page 0x" FMT_PHY_ADDRX " out: 0x" FMT_PHY_ADDRX "\n", laddr, paddr, *out);
        return true;
    }

    return false;
}

void lowerstr(unsigned char* str)
{
    while (*str != '\0')
    {
        *str++ = tolower(*str);
    }
}
