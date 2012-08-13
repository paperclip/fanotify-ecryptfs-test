
#define ROOT_DIR "/"
#define ECRYPT_DIR "/home/douglasleeder"

#include <iostream>
#include <vector>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* According to POSIX.1-2001 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include <pthread.h>

#include <stdint.h>

// Manually imported system headers
# include <linux/types.h>

# ifndef __u64
#  define __u64 uint64_t
# endif

# ifndef __aligned_u64
#  define __aligned_u64 __u64 __attribute__((aligned(8)))
# endif
# include "fanotify/fanotify.h"
# include "fanotify/fanotify-syscalllib.h"

#ifndef MAXPATHLEN
# define MAXPATHLEN 1024
#endif

#define PRINT(_X) std::cerr << _X << std::endl;
#define ASSERT assert

static std::string getPath(int fd)
{
    ASSERT(fd >= 0);
    char path[MAXPATHLEN];
    int path_len;

    sprintf(path, "/proc/self/fd/%d", fd);
    path_len = readlink(path, path, sizeof(path)-1);
    if (path_len < 0)
    {
        return "";
    }
    path[path_len] = '\0';
    return path;
}

static int addFD(int previousMaxFD, int fd, fd_set* fdset)
{
    ASSERT(fd >= 0);

    FD_SET(fd, fdset);

    if (fd > previousMaxFD)
    {
        return fd;
    }
    return previousMaxFD;
}

class ScannerThread
{
        pthread_t m_thread;
    public:
        enum STATE
        {
            CREATED = 0,
            STARTED = 1,
            BEFORE_SELECT = 2,
            AFTER_SELECT = 3,
            BEFORE_READ = 4,
            AFTER_READ = 5,
            BEFORE_WRITE = 6,
            AFTER_WRITE = 7
        };

        int m_fanotifyfd;
        volatile enum STATE m_state;
        volatile time_t m_lastStateChange;
        volatile bool m_stop;

        void setState(STATE state)
        {
            m_state = state;
            m_lastStateChange = time(0);
        }

        void printIfStale(time_t now)
        {
            if (m_state == ScannerThread::BEFORE_SELECT)
            {
                PRINT(m_thread<< " IN SELECT for "<<(now - m_lastStateChange));
            }
            else if (m_lastStateChange < now - 5)
            {
                PRINT(m_thread<<" STUCK IN "<<m_state<<" for "<<(now - m_lastStateChange));
            }
            else
            {
                PRINT(m_thread<<" NOT STUCK");
            }
        }

        ScannerThread(int fanotifyfd)
            : m_fanotifyfd(fanotifyfd),m_state(CREATED),m_lastStateChange(time(0)),m_stop(false)
        {
        }

        void handleFanotifyEvent();
        void run();
        void start();
        void join();
};

static void* scanningThreadFunction(void* arg)
{
    ScannerThread* thread = (ScannerThread*)arg;
    thread->run();
    return 0;
}

void ScannerThread::start()
{
    pthread_create(&m_thread,0,scanningThreadFunction,(void*)this);
}

void ScannerThread::join()
{
    pthread_join(m_thread, 0);
}

void ScannerThread::run()
{
    setState(ScannerThread::STARTED);
    int fanotifyfd = m_fanotifyfd;
    int maxfd = 0;
    fd_set readfds;
    fd_set errorfds;
    struct timeval timeout;
    pid_t originalParent = getppid();


    while (getppid() == originalParent && !m_stop)
    {
        FD_ZERO(&readfds); maxfd = 0;
        maxfd = addFD(maxfd,fanotifyfd,&readfds);
        errorfds = readfds;

        timeout.tv_sec = 4;
        timeout.tv_usec = 0;

        setState(ScannerThread::BEFORE_SELECT);
        int res = select(maxfd+1, &readfds, 0, &errorfds, &timeout);
        setState(ScannerThread::AFTER_SELECT);

        if (res < 0)
        {
            if (errno != EINTR)
            {
                PRINT(m_thread<<" ERROR FROM passthroughScanner select:"<<errno<<" "<<strerror(errno));
            }
            continue;
        }
        else if (res == 0)
        {
        }
        else
        {
            handleFanotifyEvent();
        }
    }
}

void ScannerThread::handleFanotifyEvent()
{
    char buf[(FAN_EVENT_METADATA_LEN / 2) * 3];
    ssize_t len;
    int fanotifyfd = m_fanotifyfd;


    setState(ScannerThread::BEFORE_READ);
    len = ::read(fanotifyfd, buf, sizeof(buf));
    setState(ScannerThread::AFTER_READ);
    if (len <= 0)
    {
        // nothing actually there - maybe another thread got it
        if (errno != EINTR && errno != EAGAIN)
        {
            PRINT(m_thread<<" no event or error: " << len << " (" << errno <<" "<<strerror(errno)<< ")");
        }
        return;
    }

    struct fanotify_event_metadata* metadata = reinterpret_cast<struct fanotify_event_metadata*>(buf);

    for (; FAN_EVENT_OK(metadata, len); metadata = FAN_EVENT_NEXT(metadata, len))
    {
        if (metadata->vers < 2)
        {
            PRINT("fanotify kernel version too old");
            throw "FIXME"; // TODO: Throw proper exception
        }

        if (metadata->vers != FANOTIFY_METADATA_VERSION)
        {
            // TODO?
            PRINT("fanotify wrong protocol version " << metadata->vers);
            throw "FIXME2"; // TODO: Throw proper exception
        }

        if ((metadata->mask & FAN_ALL_PERM_EVENTS) == 0)
        {
            close(metadata->fd);
            continue;
        }

        std::string path = getPath(metadata->fd);

        //~ {
            //~ struct stat fstatbuf;
            //~ int ret = ::fstat(metadata->fd, &fstatbuf);
            //~ if (ret < 0)
            //~ {
                //~ PRINT("Failed to fstat for "<<metadata->pid <<" "<<path);
            //~ }
        //~ }

        {
            struct fanotify_response response_struct;
            ssize_t ret;

            response_struct.fd = metadata->fd;
            response_struct.response = FAN_ALLOW;

            PRINT(m_thread<< " Responding to fanotify event for "<<metadata->pid << " "<<path);
            setState(ScannerThread::BEFORE_WRITE);
            ret = ::write(fanotifyfd, &response_struct, sizeof(response_struct));
            setState(ScannerThread::AFTER_WRITE);
            if (ret != sizeof(response_struct))
            {
                PRINT(m_thread<<" response error " << ret << " (" << errno <<" "<<strerror(errno)<< ")");
            }
        }


        {
            unsigned int flags = FAN_MARK_ADD | FAN_MARK_IGNORED_MASK;
            int ret = fanotify_mark(fanotifyfd,flags, FAN_OPEN_PERM, metadata->fd, NULL);
            if (ret < 0)
            {
                PRINT(m_thread<<" adding cache mark failed: " << ret);
            }
        }

        if (metadata->fd >= 0)
        {
            ::close(metadata->fd);
        }
    }
}

/**
 * Open the mount point directory.
 *
 * @return DONATED fd.
 */
static int openMountPoint(const char* mountpoint)
{
    // Can't keep the fd open as that prevents umount!
    int dfd = ::open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (dfd < 0)
    {
        PRINT("Can't open mountpoint "<<errno<< " "<< strerror(errno));
        exit(10);
    }
    return dfd;
}

static void changeMarkMount(int fanotifyfd, const char* mountpoint, const unsigned int flags)
{
    const uint64_t mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE;

    int dfd = openMountPoint(mountpoint);
    errno = 0;
    int ret = fanotify_mark(fanotifyfd, flags, mask, dfd, NULL);
    int error = errno;
    close(dfd);
    if (ret < 0)
    {
        PRINT(" error: " << ret<<" errno "<<error<<" strerror "<<strerror(error) << " on "<<fanotifyfd);
        exit(11);
    }
}

static void markMount(int fanotifyfd, const char* mountpoint)
{
    const unsigned int flags = FAN_MARK_ADD | FAN_MARK_MOUNT;

    PRINT("marking: " << mountpoint);

    changeMarkMount(fanotifyfd, mountpoint, flags);
}

static void unmarkMount(int fanotifyfd, const char* mountpoint)
{
    const unsigned int flags = FAN_MARK_REMOVE | FAN_MARK_MOUNT;

    PRINT("unmarking: " << mountpoint);

    changeMarkMount(fanotifyfd, mountpoint, flags);
}

int main()
{
    unsigned int init_flags = FAN_CLASS_CONTENT | FAN_UNLIMITED_MARKS | FAN_NONBLOCK;

    int connection = fanotify_init(init_flags, O_RDONLY | O_LARGEFILE); // TODO: O_RDWR and fallback enable flag if gets into 2.6.37
    if (connection < 0)
    {
        PRINT("Can't connect to fanotify" << errno);
        return 1;
    }

    // threading
    const unsigned int THREAD_COUNT = 5;
    typedef std::vector<ScannerThread*> ScannerThreadList;
    ScannerThreadList scannerThreads;

    for (unsigned int i=0;i<THREAD_COUNT;i++)
    {
        scannerThreads.push_back(new ScannerThread(connection));
    }

    for (ScannerThreadList::const_iterator it=scannerThreads.begin();it!=scannerThreads.end();it++)
    {
        (*it)->start();
    }

    // Mark filesystems
    markMount(connection, ROOT_DIR);
    markMount(connection, ECRYPT_DIR);

    // Scanning
    for(unsigned int i=0;i<120;i++)
    {
        sleep(1);
        time_t now = time(0);
        for (ScannerThreadList::const_iterator it=scannerThreads.begin();it!=scannerThreads.end();it++)
        {
            (*it)->printIfStale(now);
        }
    }

    unmarkMount(connection, ROOT_DIR);
    unmarkMount(connection, ECRYPT_DIR);

    sleep(10); // Allow pending requests

    time_t now = time(0);
    for (ScannerThreadList::const_iterator it=scannerThreads.begin();it!=scannerThreads.end();it++)
    {
        (*it)->printIfStale(now);
    }

    close(connection);
    return 0;
}
