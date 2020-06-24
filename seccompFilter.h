#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <functional>
#include <vector>
#include <initializer_list>
#include <utility>

#ifndef _SECCOMP_FILTER_H_
#define _SECCOMP_FILTER_H_
#define BPF_SYS_WHITELIST(nr)                                       \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),                  \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

namespace {

    [[noreturn]] void die_errno(const char *msg)
    {
        perror(msg);
        exit(EXIT_FAILURE);
    }

    class ForkedChild {

        pid_t child_ = 0;

        enum {
            NOT_STARTED,
            STARTED,
            FINISHED,
        } state = NOT_STARTED;

        int child_main(std::function<int()> const &fn)
        {
            prepare_child();
            return fn();
        }

    protected:

        virtual void prepare_child()
        {
            // Default does nothing.
        }

    public:

        void run(std::function<int()> const &fn)
        {
            state = STARTED;
            child_ = fork();

            if (child_ < 0) {
                die_errno("fork");
            }

            if (child_ == 0) {
                _exit(child_main(fn));
            }
        }
        
        int wait_for_child()
        {
            assert(state == STARTED);
            state = FINISHED;

            int status = 0;
            waitpid(child_, &status, 0);
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }

        ForkedChild() = default;

        ForkedChild(ForkedChild const &) = delete;
        ForkedChild &operator=(ForkedChild const &) = delete;

        virtual ~ForkedChild()
        {
            switch (state) {
            case STARTED:
                wait_for_child();
                break;
            default:
                // Nothing to do.
                break;
            }
        }
    };


    class SeccompChild final : public ForkedChild {

        std::vector<sock_filter> seccomp_filter {
            // Check architecture.
            BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,   AUDIT_ARCH_X86_64, 1, 0),
            BPF_STMT(BPF_RET | BPF_K,             SECCOMP_RET_KILL),
        };

        void extend_all() {}

        template <typename FIRST, typename... REST>
        void extend_all(FIRST first, REST... rest)
        {
            first.push_into(seccomp_filter);
            extend_all(rest...);
        }


    protected:

        void prepare_child() override
        {

            unsigned short len = seccomp_filter.size();
            assert(len == seccomp_filter.size());

            const sock_fprog prog = {
                .len = len,
                .filter = seccomp_filter.data(),
            };

            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                die_errno("PR_SET_NO_NEW_PRIVS");
            }

            if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0) != 0) {
                die_errno("PR_SET_SECCOMP");
            }

        }

    public:

        template <typename... TYPES>
        explicit SeccompChild(const TYPES &... entries)
        {
            // Load syscall number.
            seccomp_filter.push_back(BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, nr))));

            extend_all(entries...);

            // Finalize filter.
            seccomp_filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));
        }
        void setPipeFD(int fd){
            mPipeFD = fd;
        }
        uint32_t sendMessage(uint8_t *data, uint32_t data_lentgth){
            return write(mPipeFD, data, data_lentgth);
        }
        uint32_t recvMessage(uint8_t *data, uint32_t data_lentgth){
            return read(mPipeFD, data, data_lentgth);
        }
    private:
        int mPipeFD;
    };

    class SeccompWhitelist {
        unsigned sysnr_;

    public:
        explicit SeccompWhitelist(unsigned sysnr)
            : sysnr_(sysnr)
        {}

        template <typename VECTOR>
        void push_into(VECTOR &v) const
        {
            v.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))));
            v.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sysnr_, 0, 1));
            v.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }
    };

    class SeccompWhitelistWithArg {
        unsigned sysnr_;
        uint64_t arg0_;

    public:
        explicit SeccompWhitelistWithArg(unsigned sysnr, uint64_t arg0)
            : sysnr_(sysnr), arg0_(arg0)
        {}

        template <typename VECTOR>
        void push_into(VECTOR &v) const
        {
            v.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))));
            v.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sysnr_, 0, 6));

            // First half of arg
            v.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args))));
            v.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(arg0_), 0, 3));

            // Second half of arg
            v.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, sizeof(uint32_t) + (offsetof(struct seccomp_data, args))));
            v.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(arg0_ >> 32), 0, 1));

            v.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            v.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));
        }
    };

}
#endif