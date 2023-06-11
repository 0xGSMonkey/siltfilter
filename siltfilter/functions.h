#include <random>
#include <intrin.h>
#include "configuration.h"
#include "helpers.h"

void sync_fprintf(FILE* f, const char* format, ...)
{
    va_list args;
    va_start(args, format);

    if (f == stdout) {
        int ret = vsnprintf_s(stdout_buffer_pos, LINE_BUFFER_SIZE * BUFFER_LINES - (stdout_buffer_pos - stdout_buffer), _TRUNCATE, format, args);
        if (ret >= 0) stdout_buffer_pos += ret;
    }
    else if (f == stderr) {
        int ret = vsnprintf_s(stderr_buffer_pos, LINE_BUFFER_SIZE * BUFFER_LINES - (stderr_buffer_pos - stderr_buffer), _TRUNCATE, format, args);
        if (ret >= 0) stderr_buffer_pos += ret;
    }
    else {
        assert(0);
    }

    va_end(args);
}

void sync_fwrite(const void* ptr, size_t size, size_t count, FILE* f)
{
    size_t stdout_buffer_size = LINE_BUFFER_SIZE * BUFFER_LINES; // initialize to your initial buffer size
    size_t stderr_buffer_size = LINE_BUFFER_SIZE * BUFFER_LINES; // initialize to your initial buffer size

    if (f == stdout)
    {
        // Ensure there's enough space
        if ((stdout_buffer_pos - stdout_buffer) + size * count > stdout_buffer_size)
        {
            // Reallocate the buffer to a larger size
            stdout_buffer_size *= 2;
            char* stdout_buffer = (char*)malloc(stdout_buffer_size);
            //stdout_buffer = static_cast<char*>(realloc(stdout_buffer, stdout_buffer_size));
        }

        // Copy data to the buffer
        memcpy(stdout_buffer_pos, ptr, size * count);
        stdout_buffer_pos += size * count;

        // frees the buffer
        free(stdout_buffer);
    }
    else if (f == stderr)
    {
        // Ensure there's enough space
        if ((stderr_buffer_pos - stderr_buffer) + size * count > stderr_buffer_size)
        {
            // Reallocate the buffer to a larger size
            stderr_buffer_size *= 2;
            char* stderr_buffer = (char*)malloc(stderr_buffer_size);
            //stderr_buffer = static_cast<char*>(realloc(stderr_buffer, stderr_buffer_size));
        }

        // Copy data to the buffer
        memcpy(stderr_buffer_pos, ptr, size * count);
        stderr_buffer_pos += size * count;

        // frees the buffer
        free(stderr_buffer);
    }
    else
    {
        assert(0);
    }
}

void sync_fflush(FILE* f, bool force)
{
    if (f == stdout) {
        stdout_sync_counter++;
        if (stdout_sync_counter == SYNC_LINES_STDOUT || force) {
            stdout_sync_counter = 0;
            EnterCriticalSection(&output_mutex);
            fwrite(stdout_buffer, 1, stdout_buffer_pos - stdout_buffer, f);
            fflush(f);
            LeaveCriticalSection(&output_mutex);
            stdout_buffer_pos = stdout_buffer;
        }
    }
    else if (f == stderr) {
        stderr_sync_counter++;
        if (stderr_sync_counter == SYNC_LINES_STDERR || force) {
            stderr_sync_counter = 0;
            EnterCriticalSection(&output_mutex);
            fwrite(stderr_buffer, 1, stderr_buffer_pos - stderr_buffer, f);
            fflush(f);
            LeaveCriticalSection(&output_mutex);
            stderr_buffer_pos = stderr_buffer;
        }
    }
    else {
        assert(0);
    }
}

void zero_insn_end(insn_t* insn, int marker)
{
    int i;
    for (i = marker; i < MAX_INSN_LENGTH; i++) {
        insn->bytes[i] = 0;
    }
}

bool increment_range(insn_t* insn, int marker)
{
    int i = marker - 1;
    zero_insn_end(insn, marker);

    if (i >= 0) {
        insn->bytes[i]++;
        while (insn->bytes[i] == 0) {
            i--;
            if (i < 0) {
                break;
            }
            insn->bytes[i]++;
        }
    }

    insn->len = marker;

    return i >= 0;
}

void print_insn(FILE* f, insn_t* insn)
{
    int i;
    for (i = 0; i < sizeof(insn->bytes); i++) {
        sync_fprintf(f, "%02x", insn->bytes[i]);
    }
}

void print_range(FILE* f, range_t* range)
{
    print_insn(f, &range->start);
    sync_fprintf(f, ";");
    print_insn(f, &range->end);
}

// Must call before creating new processes
void initialize_ranges(void)
{
    if (range_marker == NULL) {
        HANDLE hMapFile;

        hMapFile = CreateFileMapping(
            INVALID_HANDLE_VALUE,    // use paging file
            NULL,                    // default security
            PAGE_READWRITE,          // read/write access
            0,                       // maximum object size (high-order DWORD)
            sizeof(*range_marker),   // maximum object size (low-order DWORD)
            TEXT("RangeMarkerMapObject"));  // name of mapping object

        if (hMapFile == NULL)
        {
            printf("Could not create file mapping object (%d).\n", GetLastError());
            return;
        }

        range_marker = (insn_t*)MapViewOfFile(hMapFile, // handle to map object
            FILE_MAP_ALL_ACCESS,  // read/write permission
            0,
            0,
            sizeof(*range_marker));

        if (range_marker == NULL)
        {
            printf("Could not map view of file (%d).\n", GetLastError());
            CloseHandle(hMapFile);
            return;
        }

        *range_marker = total_range.start;
    }
}

void free_ranges(void)
{
    if (range_marker != NULL) {
        UnmapViewOfFile(range_marker);

        // We also need to close the handle to the memory-mapped file
        HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, TEXT("RangeMarkerMapObject"));
        if (hMapFile != NULL) {
            CloseHandle(hMapFile);
        }

        range_marker = NULL;
    }
}


#if USE_CAPSTONE
int print_asm(FILE* f)
{
    if (output == TEXT) {
        uint8_t* code = inj.i.bytes;
        size_t code_size = MAX_INSN_LENGTH;
        uint64_t address = (uintptr_t)packet_buffer;

        if (cs_disasm_iter(
            capstone_handle,
            (const uint8_t**)&code,
            &code_size,
            &address,
            capstone_insn)
            ) {
            sync_fprintf(
                f,
                "%10s %-45s (%2d)",
                capstone_insn[0].mnemonic,
                capstone_insn[0].op_str,
                (int)(address - (uintptr_t)packet_buffer)
            );
        }
        else {
            sync_fprintf(
                f,
                "%10s %-45s (%2d)",
                "(unk)",
                " ",
                (int)(address - (uintptr_t)packet_buffer)
            );
        }
        expected_length = (int)(address - (uintptr_t)packet_buffer);
    }

    return 0;
}
#endif

void print_mc(FILE* f, int length)
{
    int i;
    bool p = false;
    if (!is_prefix(inj.i.bytes[0])) {
        sync_fprintf(f, " ");
        p = true;
    }
    for (i = 0; i < length && i < MAX_INSN_LENGTH; i++) {
        sync_fprintf(f, "%02x", inj.i.bytes[i]);
        if (
            !p &&
            i < MAX_INSN_LENGTH - 1 &&
            is_prefix(inj.i.bytes[i]) &&
            !is_prefix(inj.i.bytes[i + 1])
            ) {
            sync_fprintf(f, " ");
            p = true;
        }
    }
}

bool is_prefix(uint8_t pre)
{
    return
        pre == 0xf0 || /* lock */
        pre == 0xf2 || /* repne / bound */
        pre == 0xf3 || /* rep */
        pre == 0x2e || /* cs / branch taken */
        pre == 0x36 || /* ss / branch not taken */
        pre == 0x3e || /* ds */
        pre == 0x26 || /* es */
        pre == 0x64 || /* fs */
        pre == 0x65 || /* gs */
        pre == 0x66 || /* data / operand override*/
        pre == 0x67    /* addr override*/
#ifdef _M_AMD64
        || (pre >= 0x40 && pre <= 0x4f) /* rex */
#endif
        ;
}

int prefix_count(void)
{
    int i;
    for (i = 0; i < MAX_INSN_LENGTH; i++) {
        if (!is_prefix(inj.i.bytes[i])) {
            return i;
        }
    }
    return i;
}

bool has_dup_prefix(void)
{
    int i;
    int byte_count[256];
    memset(byte_count, 0, 256 * sizeof(int));

    for (i = 0; i < MAX_INSN_LENGTH; i++) {
        if (is_prefix(inj.i.bytes[i])) {
            byte_count[inj.i.bytes[i]]++;
        }
        else {
            break;
        }
    }

    for (i = 0; i < 256; i++) {
        if (byte_count[i] > 1) {
            return true;
        }
    }

    return false;
}

//TODO: can't blacklist 00
bool has_opcode(uint8_t* op)
{
    int i, j;
    for (i = 0; i < MAX_INSN_LENGTH; i++) {
        if (!is_prefix(inj.i.bytes[i])) {
            j = 0;
            do {
                if (i + j >= MAX_INSN_LENGTH || op[j] != inj.i.bytes[i + j]) {
                    return false;
                }
                j++;
            } while (op[j]);

            return true;
        }
    }
    return false;
}

//TODO: can't blacklist 00
bool has_prefix(uint8_t* pre)
{
    int i, j;
    for (i = 0; i < MAX_INSN_LENGTH; i++) {
        if (is_prefix(inj.i.bytes[i])) {
            j = 0;
            do {
                if (inj.i.bytes[i] == pre[j]) {
                    return true;
                }
                j++;
            } while (pre[j]);
        }
        else {
            return false;
        }
    }
    return false;
}

//void preamble_start(void) {
//    // Your preamble code here
//}
void preamble()
{
#ifdef _M_AMD64
    preamble_start = 0;
    unsigned __int64 flags = __readeflags();
    flags |= TF;
    __writeeflags(flags);
    preamble_end = (char*)'\xff';
#else
    unsigned long flags = __readeflags();
    flags |= TF;
    __writeeflags(flags);
#endif
}
//void preamble_end(void) {
//    // Nothing here - this function is just a placeholder
//}

void inject(int insn_size)
{
    int i;
    ptrdiff_t preamble_length = ((ptrdiff_t)preamble_end - (ptrdiff_t)preamble_start) / 4;
    static bool have_state = false;

    if (!USE_TF) { preamble_length = 0; }

    packet = (char*)packet_buffer + PAGE_SIZE - insn_size - preamble_length;

    for (i = 0; i < preamble_length * 2; i++) {
        ((char*)packet)[i] = ((char*)&preamble_start)[i];
    }
    for (i = 0; i < MAX_INSN_LENGTH && i < insn_size; i++) {
        ((char*)packet)[i + preamble_length] = inj.i.bytes[i];
    }

    if (config.enable_null_access) {
        void* p = NULL;
        memset(p, 0, PAGE_SIZE);
    }

    if (!have_state) {
        have_state = true;
        // Configure an exception handler here?
        __ud2();  // This intrinsic triggers a UD2 instruction, causing a SIGILL.
        //GetThreadContext(GetCurrentThread(), (LPCONTEXT)injector_state);
    }

    // Configure a fault handler here.
    // The fault handler would need to be done with Structured Exception Handling.

    // This is very system specific and could be different based on the architecture and the compiler.
#if _M_AMD64
    // Set general-purpose registers to the saved state.
    _mm_setcsr(injector_state.Rax);
    _mm_setcsr(injector_state.Rbx);
    _mm_setcsr(injector_state.Rcx);
    _mm_setcsr(injector_state.Rdx);
    _mm_setcsr(injector_state.Rsi);
    _mm_setcsr(injector_state.Rdi);
    _mm_setcsr(injector_state.R8);
    _mm_setcsr(injector_state.R9);
    _mm_setcsr(injector_state.R10);
    _mm_setcsr(injector_state.R11);
    _mm_setcsr(injector_state.R12);
    _mm_setcsr(injector_state.R13);
    _mm_setcsr(injector_state.R14);
    _mm_setcsr(injector_state.R15);
    _mm_setcsr(injector_state.Rbp);
    _mm_setcsr(injector_state.Rsp);

    // Then use some sort of function call or jump to the code at `packet`.
    ((void (*)())packet)();
#else
    // Set general-purpose registers to the saved state.
    _mm_setcsr(inject_state.eax);
    _mm_setcsr(inject_state.ebx);
    _mm_setcsr(inject_state.ecx);
    _mm_setcsr(inject_state.edx);
    _mm_setcsr(inject_state.esi);
    _mm_setcsr(inject_state.edi);
    _mm_setcsr(inject_state.ebp);
    _mm_setcsr(inject_state.esp);

    // Then use some sort of function call or jump to the code at `packet`.
    ((void (*)())packet)();
#endif
}



/* note: this should provide a more even distribution */
void get_rand_insn_in_range(range_t* r)
{
    // Make sure to instantiate the engine and distribution only once
    std::random_device rd;  // Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd()); // Standard mersenne_twister_engine seeded with rd()

    static uint8_t inclusive_end[MAX_INSN_LENGTH];
    int i;
    bool all_max = true;
    bool all_min = true;

    memcpy(inclusive_end, &r->end.bytes, MAX_INSN_LENGTH);
    i = MAX_INSN_LENGTH - 1;
    while (i >= 0) {
        inclusive_end[i]--;
        if (inclusive_end[i] != 0xff) {
            break;
        }
        i--;
    }

    for (i = 0; i < MAX_INSN_LENGTH; i++) {
        std::uniform_int_distribution<> distr(0, 255); // define the range
        if (all_max && all_min) {
            distr = std::uniform_int_distribution<>(r->start.bytes[i], inclusive_end[i]);
        }
        else if (all_max) {
            distr = std::uniform_int_distribution<>(0, inclusive_end[i]);
        }
        else if (all_min) {
            distr = std::uniform_int_distribution<>(r->start.bytes[i], 255);
        }
        inj.i.bytes[i] = distr(gen);

        all_max = all_max && (inj.i.bytes[i] == inclusive_end[i]);
        all_min = all_min && (inj.i.bytes[i] == r->start.bytes[i]);
    }
}


void pin_core(void)
{
    if (config.force_core) {
        DWORD_PTR mask = 1 << config.core; // assuming config.core is the number of the core you want to pin to
        if (!SetThreadAffinityMask(GetCurrentThread(), mask)) {
            printf("error: failed to set cpu\n");
            exit(1);
        }
        // Now, all fibers running on this thread will also run on the CPU core specified by config.core.
    }
}

void tick(void)
{
    static uint64_t t = 0;
    if (config.show_tick) {
        t++;
        if ((t & TICK_MASK) == 0) {
            fprintf(stderr, "t: ");
            print_mc(stderr, 8);
            fprintf(stderr, "... ");
#if USE_CAPSTONE
            print_asm(stderr);
            fprintf(stderr, "\t");
#endif
            give_result(stderr);
            fflush(stderr);
        }
    }
}

void pretext(void)
{
    /* assistive output for analyzing hangs in text mode */
    if (output == TEXT) {
        sync_fprintf(stdout, "r: ");
        print_mc(stdout, 8);
        sync_fprintf(stdout, "... ");
#if USE_CAPSTONE
        print_asm(stdout);
        sync_fprintf(stdout, " ");
#endif
        sync_fflush(stdout, false);
    }
}

void usage(void)
{
    printf("injector [-b|-r|-t|-d] [-R|-T] [-x] [-0] [-D] [-N]\n");
    printf("\t[-s seed] [-B brute_depth] [-P max_prefix]\n");
    printf("\t[-i instruction] [-e instruction]\n");
    printf("\t[-c core] [-X blacklist]\n");
    printf("\t[-j jobs] [-l range_bytes]\n");
}

void help(void)
{
    printf("injector [OPTIONS...]\n");
    printf("\t[-b|-r|-t|-d] ....... mode: brute, random, tunnel, directed (default: tunnel)\n");
    printf("\t[-R|-T] ............. output: raw, text (default: text)\n");
    printf("\t[-x] ................ show tick (default: %d)\n", config.show_tick);
    printf("\t[-0] ................ allow null dereference (requires sudo) (default: %d)\n", config.enable_null_access);
    printf("\t[-D] ................ allow duplicate prefixes (default: %d)\n", config.allow_dup_prefix);
    printf("\t[-N] ................ no nx bit support (default: %d)\n", config.nx_support);
    printf("\t[-s seed] ........... in random search, seed (default: time(0))\n");
    printf("\t[-B brute_depth] .... in brute search, maximum search depth (default: %d)\n", config.brute_depth);
    printf("\t[-P max_prefix] ..... maximum number of prefixes to search (default: %d)\n", config.max_prefix);
    printf("\t[-i instruction] .... instruction at which to start search, inclusive (default: 0)\n");
    printf("\t[-e instruction] .... instruction at which to end search, exclusive (default: ff..ff)\n");
    printf("\t[-c core] ........... core on which to perform search (default: any)\n");
    printf("\t[-X blacklist] ...... blacklist the specified instruction\n");
    printf("\t[-j jobs] ........... number of simultaneous jobs to run (default: %d)\n", config.jobs);
    printf("\t[-l range_bytes] .... number of base instruction bytes in each sub range (default: %d)\n", config.range_bytes);
}