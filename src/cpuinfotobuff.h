/******************************************************************************
 * cpuinfotobuff.h
 *
 * Outputs cpuid-dump, cpu-info, cache-info, isa-info to a buffer
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

// Returns 0 on success, negative number on failure in which case errno is set
// buff must be at least 1K. 16KB should be enough. Will return error if runs
// out of buffer
int cpuinfotobuff(char * _buff, size_t _buffLen);

#ifdef __cplusplus
}
#endif
