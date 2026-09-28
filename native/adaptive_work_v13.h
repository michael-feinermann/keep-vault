#ifndef KEEPVAULT_ADAPTIVE_WORK_V13_H
#define KEEPVAULT_ADAPTIVE_WORK_V13_H
#include <stddef.h>
/* The preferred grain controls overhead on ordinary machines, never the total
 * worker count. Shrink it to leave about four disjoint claims per granted
 * worker on larger topologies; a complete primitive block is the only minimum.
 * Division avoids overflowing total_blocks or workers * 4. */
#if defined(_MSC_VER) && !defined(__cplusplus)
#define KEEPVAULT_CTR_INLINE __inline
#else
#define KEEPVAULT_CTR_INLINE inline
#endif
static KEEPVAULT_CTR_INLINE size_t keepvault_v13_claim_blocks(size_t total_blocks, size_t preferred_blocks, size_t workers)
{
    size_t adaptive = workers == 0 ? total_blocks : total_blocks / workers / 4;
    if (adaptive == 0) adaptive = 1;
    return adaptive < preferred_blocks ? adaptive : preferred_blocks;
}
#undef KEEPVAULT_CTR_INLINE
#endif
