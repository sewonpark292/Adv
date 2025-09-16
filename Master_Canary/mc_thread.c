// Name: mc_thread.c
// Compile: gcc -o mc_thread mc_thread.c -pthread -no-pie
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void giveshell() { execve("/bin/sh", 0, 0); }
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void read_bytes(char *buf, int size) {
  int i;

  for (i = 0; i < size; i++)
    if (read(0, buf + i*8, 8) < 8)
      return;
}

void thread_routine() {
  //buf is located near by thread
  //0x7ffff7da4000 0x7ffff7dcc000 r--p 28000 0 /usr/lib/x86_64-linux-gnu/libc.so.6
  char buf[256]; 
  int size = 0;
  printf("Size: ");
  scanf("%d", &size); //user가 원하는 만큼 입력을 받음
  printf("Data: ");
  //!!BOF vuln!!
  //buf에 size(input_value) * 8 만큼 입력 받는데 
  //buf를 마치 스택처럼 8byte씩 읽어들이는데
  //read() 반환값: 읽어들인 데이터 길이
  read_bytes(buf, size); 
}

int main() {
  pthread_t thread_t; //스레드 생성 시 ID 저장됨.

  init();
  //pthread_create(1, 2, 3, 4)
  //arg1: 스레드 생성에 성공했을 시 ID가 저장된다.
  //arg2: NULL: default attributes thread
  //arg3: 스레드 생성 시 시작할 함수를 지정한다.
  //arg4: arg3의 함수 호출 시 사용될 인자
  if (pthread_create(&thread_t, NULL, (void *)thread_routine, NULL) < 0) {
    perror("thread create error:");
    exit(0);
  }
  //pthread_join(1, 2)
  //arg1: thread_t 가 종료될 때 까지 기다린다.
  //arg2: null이 아니면, 
  pthread_join(thread_t, 0);
  return 0;
}
