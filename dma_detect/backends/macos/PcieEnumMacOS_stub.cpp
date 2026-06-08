/* macOS DMA-detect stub — IOKit backend pending. */
#include <cstring>
#include "../../include/horkos/dma_detect.h"
extern "C" int hk_dma_scan(hk_dma_report *out) {
    if (out) { memset(out, 0, sizeof(*out)); out->scan_error = 1; }
    return -1;
}
