// gcc -o master master.c -pthread
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

char *global_buffer; //전역변수 8byte 포인터

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() { //get_shell 함수가 있네
    system("/bin/sh");
}

void *thread_routine() { // 
    char buf[256]; // thread의 지역변수 -> thread 주변 매핑 (stack 영역 X)

    global_buffer = buf; // 전역변수 포인터가 buf를 가리키게 함.
}

void read_bytes(char *buf, size_t size) {
    size_t sz = 0;
    size_t idx = 0;
    size_t tmp;

    while (sz < size) {
        tmp = read(0, &buf[idx], 1); // 1byte씩 읽음.
        if (tmp != 1) { // 1byte가 아닌 경우 종료
            exit(-1);
        }
        idx += 1;
        sz += 1;
    }
    return;
}

int main(int argc, char *argv[]) {
    size_t size = 0;
    pthread_t thread_t; // 스레드 구조체를 이용한 스레드 생성
    int idx = 0;
    char leave_comment[32]; // 지역변수 버퍼

    initialize();

    while (1) {
        printf("1. Create thread\n");
        printf("2. Input\n");
        printf("3. Exit\n");
        printf("> ");
        scanf("%d", &idx); // sendline

        switch (idx) {
            case 1:
                if (pthread_create(&thread_t, NULL, thread_routine, NULL) < 0) { //스레드 생성 함수
                    perror("thread create error");
                    exit(0);
                }
                break;
            case 2:
                printf("Size: ");
                scanf("%lu", &size); // buf: 256byte , sendline

                printf("Data: ");
                read_bytes(global_buffer, size); // !!Vuln!! BOF , send

                printf("Data: %s", global_buffer); //저장된 문자열 출력
                break;
            case 3:
                printf("Leave comment: ");
                read(0, leave_comment, 1024); // leave_comment: 32byte , send
                return 0;
            default:
                printf("Nope\n");
                break;
        }
    }

    return 0;
}