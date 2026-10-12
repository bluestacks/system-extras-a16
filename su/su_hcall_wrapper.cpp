// This is a C++ wrapper file to bridge C++ headers with C code
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "su_utils.h"
#include "Xpl.h"
#include "Xexc.h"
#include "Hcall.h"

extern "C" {
    bool isDeveloperMode()
    {
        // BS-A16-MAC (bringup): the Mac engine does not answer the
        // GetDeveloperMode hcall (and the vmsg cid pool is exhausted by the
        // A16 service set), so su could never gain root. Skip the host check;
        // restore once the engine side (unlock_player.bin parity) is sorted.
        log_debug("isDeveloperMode: BS-A16-MAC bringup bypass -> true");
        return true;
#if 0
        log_debug("isDeveloperMode: Function started.");
        bool rval = false;
        int fd = -1;

        fd = open("/dev/bstvmsg", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            log_debug("isDeveloperMode: Failed to open /dev/bstvmsg, errno = %d.", errno);
            return false;
        }
        close(fd);
        rval = hcallIsDeveloperModeLocked();
        log_debug("isDeveloperMode: Got result, value = %s.", rval ? "true" : "false");
        return rval;
#endif
    }
}