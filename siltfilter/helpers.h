/* helpers */
// Not sure what is going on here tbh.
#define STR(x) #x
#define XSTR(x) STR(x)

/* x86/64 */

#define UD2_SIZE  2 // Undefined Instruction
#define PAGE_SIZE 4096
#define TF        0x100 // Trap Flag

#define USE_TF true /* leave true, except when synthesizing some specific instructions */

#define MAX_INSN_LENGTH 15 /* actually 15 */
/* fault handler tries to use fault address to make an initial guess of
 * instruction length; but length of jump instructions can't be determined from
 * trap alone */
 /* set to this if something seems wrong */
#define JMP_LENGTH 16 // So, this essentially just truncates the length to 16 if insn exceeds 15. Not sure if this is good enough for 64bit machines

#define TICK_MASK 0xffff

#define RAW_REPORT_INSN_BYTES 16

#define RAW_REPORT_DISAS_MNE false /* sifter assumes false */
#define RAW_REPORT_DISAS_MNE_BYTES 16
#define RAW_REPORT_DISAS_OPS false /* sifter assumes false */
#define RAW_REPORT_DISAS_OPS_BYTES 32
#define RAW_REPORT_DISAS_LEN true  /* sifter assumes true */
#define RAW_REPORT_DISAS_VAL true  /* sifter assumes true */

#define MAX_BLACKLIST 128

/* synchronized output */
#define LINE_BUFFER_SIZE 256
#define BUFFER_LINES 16
#define SYNC_LINES_STDOUT BUFFER_LINES /* must be <= BUFFER_LINES */
#define SYNC_LINES_STDERR BUFFER_LINES /* must be <= BUFFER_LINES */
char stdout_buffer[LINE_BUFFER_SIZE * BUFFER_LINES];
char* stdout_buffer_pos = stdout_buffer;
int stdout_sync_counter = 0;
char stderr_buffer[LINE_BUFFER_SIZE * BUFFER_LINES];
char* stderr_buffer_pos = stderr_buffer;
int stderr_sync_counter = 0;