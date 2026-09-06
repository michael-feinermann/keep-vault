#include <stdio.h>
#include "../external/Skein-reference/NIST/CD/Reference_Implementation/skein_block.c"

int main(void)
    {
    /* Actual schedule/state array lengths, including an empty range.
       Volatile reads observe the completed writes in an optimized build. */
    static const size_t lengths[] = { 0, 3, 4, 5, 8, 9, 16, 17 };
    const u64b_t sentinel = SKEIN_MK_64(0xA596C37E,0x1BF04D82);
    u64b_t storage[19];
    volatile u64b_t *observed = storage;
    size_t test,index;
    for (test = 0; test < sizeof(lengths)/sizeof(lengths[0]); ++test)
        {
        const size_t count = lengths[test];
        for (index = 0; index < sizeof(storage)/sizeof(storage[0]); ++index)
            observed[index] = sentinel;
        Skein_Secure_Zero_Local(storage+1,count*sizeof(storage[0]));
        for (index = 0; index < sizeof(storage)/sizeof(storage[0]); ++index)
            {
            const u64b_t expected = index > 0 && index <= count ? 0 : sentinel;
            if (observed[index] != expected)
                {
                fprintf(stderr,"skein_word_wipe_failure: length=%zu index=%zu\n",count,index);
                return 3;
                }
            }
        }
    puts("skein_word_wipe=complete_and_bounded cases=8");
    return 0;
    }
