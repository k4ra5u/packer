#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <time.h>
#include <link.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/shm.h>

#include "nyx.h"
#include "misc/crash_handler.h"
#include "misc/harness_state.h"
#include "netfuzz/syscalls.h"

#define MAX_RETRY_TIME 60
#define RECV_BUFFER_SIZE 0x100000
#define min(a, b) ((a) < (b) ? (a) : (b))


size_t input_buffer_size = 0;
void* trace_buffer = NULL;
int trace_buffer_size = 0;
unsigned char* execution_path = NULL;
struct timeval timeout;
kAFL_payload* payload_buffer = NULL;
unsigned char* __quic_response = NULL;

void capabilites_configuration(bool timeout_detection, bool agent_tracing);
void start_target();
void get_payload(kAFL_payload* payload_buffer);




void capabilites_configuration(bool timeout_detection, bool agent_tracing) {
    static bool done = false;

    if(!done){
        init_syscall_fptr();

        hprintf("[capablities] agent_tracing: %d\n", agent_tracing);

        host_config_t host_config;
        kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

        if(host_config.host_magic != NYX_HOST_MAGIC){
            habort("Error: NYX_HOST_MAGIC not found in host configuration - You are probably using an outdated version of QEMU-Nyx...");
        }

        if(host_config.host_version != NYX_HOST_VERSION){ 
            habort("Error: NYX_HOST_VERSION not found in host configuration - You are probably using an outdated version of QEMU-Nyx...");
        }

        hprintf("[capablities] host_config.bitmap_size: 0x%"PRIx64"\n", host_config.bitmap_size);
        hprintf("[capablities] host_config.payload_buffer_size: 0x%"PRIx64"\n", host_config.payload_buffer_size);

        input_buffer_size = host_config.payload_buffer_size;

        agent_config_t agent_config = {0};

        agent_config.agent_magic = NYX_AGENT_MAGIC;
        agent_config.agent_version = NYX_AGENT_VERSION;
        agent_config.agent_timeout_detection = (uint8_t)timeout_detection;
        agent_config.agent_tracing = (uint8_t)agent_tracing;

        agent_config.coverage_bitmap_size = host_config.bitmap_size;
        trace_buffer_size = host_config.bitmap_size;

        /* Create trace_buffer with shared memory */
        int shmid = shmget(0x1337, host_config.bitmap_size, IPC_CREAT | 0666);
        if (shmid == -1) {
            habort("Error: Failed to create shared memory segment...");
        }
        hprintf("[capablities] trace_buffer shmid: %d\n", shmid);
        char buffer[20] = {0};
        sprintf(buffer, "%d", shmid);
        setenv("__AFL_SHM_ID", buffer, 1);
        sprintf(buffer, "%d", host_config.bitmap_size);
        setenv("__AFL_SHM_ID_SIZE", buffer, 1);
        trace_buffer = shmat(shmid, NULL, 0);
        hprintf("[capablities] trace_buffer: %p\n", trace_buffer);
        memset(trace_buffer, 0xff, agent_config.coverage_bitmap_size);

        agent_config.trace_buffer_vaddr = (uintptr_t)trace_buffer;
        
        /* Create quic_response with shared memory */
        shmid = shmget(0x1338, 0x100000, IPC_CREAT | 0666);
        if (shmid == -1) {
            habort("Error: Failed to create shared memory segment...");
        }
        hprintf("[capablities] quic_response shmid: %d\n", shmid);
        sprintf(buffer, "%d", shmid);
        setenv("__QUIC_RESPONSE", buffer, 1);
        sprintf(buffer, "%d", 0x100000);
        setenv("__QUIC_RESPONSE_SIZE", buffer, 1);
        __quic_response = shmat(shmid, NULL, 0);
        hprintf("[capablities] __QUIC_RESPONSE: %p\n", __quic_response);
        memset(__quic_response, 0x0, 0x100000);
        
        agent_config.quic_response_vaddr = (uintptr_t)__quic_response;

        /* Create execution_path with shared memory */
        shmid = shmget(0x1339, 0x100000, IPC_CREAT | 0666);
        if (shmid == -1) {
            habort("Error: Failed to create shared memory segment...");
        }
        hprintf("[capablities] payload shmid: %d\n", shmid);
        sprintf(buffer, "%d", shmid);
        setenv("__EXECUTION_PATH", buffer, 1);
        sprintf(buffer, "%d", 0x100000);
        setenv("__EXECUTION_PATH_SIZE", buffer, 1);
        execution_path = shmat(shmid, NULL, 0);
        hprintf("[capablities] payload: %p\n", execution_path);
        memset(execution_path, 0x0, 0x100000);
        
        agent_config.execution_path_vaddr = (uintptr_t)execution_path;

        agent_config.agent_non_reload_mode = get_harness_state()->fast_exit_mode;

        kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
        
        done = true;
    }
}

void start_target() {

    /* Run start script */
    system("nohup /tmp/target/tcpdump -i any -s 0 -w /tmp/1.pcap udp 2>&1 &");
    int ret = system("RUST_BACKTRACE=1 nohup /tmp/target/quic_converter_nyx 2>&1 |tee /tmp/target/log_convert.txt &");
    if (ret != 0) {
        habort("[harness] Error: Failed to run target startup script");
    }
    sleep(1);
}

void get_payload(kAFL_payload* payload_buffer) {
    if(input_buffer_size == 0) {
        habort("[harness] Error: The size of the input buffer has not been specified by the host...");
    }

    mlock(payload_buffer, (size_t)input_buffer_size);
    memset(payload_buffer, 0, input_buffer_size);

    hprintf("[harness] payload buffer is mapped at %p (size: 0x%lx)\n", payload_buffer, input_buffer_size);

    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);
}


int main() {
    hprintf("[harness] Harness started!\n");
    capabilites_configuration(false, true);

    payload_buffer = mmap(NULL, input_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (payload_buffer == MAP_FAILED) {
        habort("[harness] Error: Failed to create payload buffer mmap");
    }
    memset(payload_buffer, 0, input_buffer_size);

    hprintf("[harness] Starting target...\n");
    start_target();

    get_payload(payload_buffer);


    FILE *file = fopen("/tmp/1.pcap", "rb");
    if (file == NULL) {
        hprintf("[harness] Error: Failed to open target log file log_convert.txt\n");
    } else {    
        char buffer[RECV_BUFFER_SIZE];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0'; // Null-terminate the string
            hprintf("[harness] Target log: (log_convert.txt) %s\n", buffer);
        }   
        fclose(file);
    }

    file = fopen("/tmp/target/log_convert.txt", "r");
    if (file == NULL) {
        hprintf("[harness] Error: Failed to open target log file log_convert.txt\n");
    } else {    
        char buffer[RECV_BUFFER_SIZE];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0'; // Null-terminate the string
            hprintf("[harness] Target log: (log_convert.txt) %s\n", buffer);
        }   
        fclose(file);
    }




    kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);
    memcpy(execution_path+1, payload_buffer->data+1, payload_buffer->size -1);
    execution_path[0] = payload_buffer->data[0];
    char buffer[RECV_BUFFER_SIZE];

    while (1) {

        if (execution_path[0] != 0) {
            hprintf("[harness] Execution path is not empty, processing payload...\n");
            // sleep(0.05);
            sleep(0.05);
        }
        else {
                FILE *file = fopen("/tmp/1.pcap", "rb");
                if (file != NULL) {   
                    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
                    if (bytes_read > 0) {
                        // buffer[bytes_read] = '\0'; // Null-terminate the string
                        memcpy(execution_path, buffer, bytes_read);
                    }   
                    fclose(file);
                }
            break;
        }
    }

    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
}
