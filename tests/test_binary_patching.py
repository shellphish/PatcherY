import unittest
from pathlib import Path

from patchery.generator import LLMPlanPatchGenerator
from patchery.data import PoI, PoICluster, Program, ProgramAlert
from patchery.kumushi.code_parsing import CodeFunction

SOURCE = """
ssize_t
ngx_sendfile_r(ngx_connection_t *c, ngx_buf_t *file, size_t size)
{
    struct stat sb;
    u_char *buf;
    u_char *rev;
    ssize_t n;

    if (fstat(file->file->fd, &sb) != 0) {
        return NGX_ERROR;
    }

    buf = ngx_palloc(c->pool, ngx_file_size(&sb));

    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (read( file->file->fd, buf, ngx_file_size(&sb)) == NGX_ERROR) {
        return NGX_ERROR;
    }

    lseek(file->file->fd, 0, SEEK_SET);

    rev = ngx_alloc(NGX_SENDFILE_R_MAXSIZE, c->log);

    if ( rev == NULL ) {
        return NGX_ERROR;
    }

    for ( int i = file->file_pos + size - 1, j = 0; i >= file->file_pos; i--, j++) {
        rev[j] = buf[i];
    }

    n = c->send(c, rev, size);

    ngx_pfree(c->pool, buf);
    ngx_free(rev);

    return n;
}
"""

ANGR_CODE = """
long long ngx_sendfile_r(struct_3 *a0, struct_0 *a1, unsigned long long a2)
{
    unsigned int v0;  // [bp-0xd8]
    unsigned int v1;  // [bp-0xd4]
    unsigned long long v2;  // [bp-0xd0]
    char *v3;  // [bp-0xc8]
    char *v4;  // [bp-0xc0]
    char v5;  // [bp-0xb8]
    char v6;  // [bp-0x88]
    unsigned long long v7;  // [bp-0x10]

    if (fstat64(a1->field_40->field_0, &v5))
    {
        v7 = -0x1;
        return -0x1;
    }
    v4 = ngx_palloc(a0->field_68, *((long long *)&v6));
    if (!v4)
    {
        v7 = -0x1;
        return -0x1;
    }
    else if (read(a1->field_40->field_0, v4, *((long long *)&v6)) == -1)
    {
        v7 = -1;
        return -1;
    }
    else
    {
        lseek64(a1->field_40->field_0, 0, 0);
        v3 = ngx_alloc(100, a0->field_60);
        if (!v3)
        {
            v7 = -1;
            return -1;
        }
        v1 = a1->field_10 + a2 - 1;
        for (v0 = 0; v1 >= a1->field_10; v0 += 1)
        {
            v3[v0] = v4[v1];
            v1 -= 1;
        }
        v2 = a0->field_30(a0, v3, a2);
        ngx_pfree(a0->field_68, v4);
        free(v3);
        v7 = v2;
        return v7;
    }
}
"""

GHIDRA_CODE = """
ssize_t ngx_sendfile_r(ngx_connection_t *c,ngx_buf_t *file,size_t size)
{
  int iVar1;
  void *__buf;
  ssize_t sVar2;
  u_char *__ptr;
  int local_d8;
  int local_d4;
  int j;
  int i;
  ssize_t n;
  u_char *rev;
  u_char *buf;
  stat sb;
  size_t size_local;
  ngx_buf_t *file_local;
  ngx_connection_t *c_local;
  
  sb.__glibc_reserved[2] = size;
  iVar1 = fstat64(file->file->fd,(stat64 *)&buf);
  if (iVar1 == 0) {
    __buf = ngx_palloc(c->pool,sb.st_rdev);
    if (__buf == (void *)0x0) {
      c_local = (ngx_connection_t *)0xffffffffffffffff;
    }
    else {
      sVar2 = read(file->file->fd,__buf,sb.st_rdev);
      if (sVar2 == -1) {
        c_local = (ngx_connection_t *)0xffffffffffffffff;
      }
      else {
        lseek64(file->file->fd,0,0);
        __ptr = (u_char *)ngx_alloc(100,c->log);
        if (__ptr == (u_char *)0x0) {
          c_local = (ngx_connection_t *)0xffffffffffffffff;
        }
        else {
          local_d4 = (int)file->file_pos + (int)sb.__glibc_reserved[2];
          local_d8 = 0;
          while (local_d4 = local_d4 + -1, file->file_pos <= (long)local_d4) {
            __ptr[local_d8] = *(u_char *)((long)__buf + (long)local_d4);
            local_d8 = local_d8 + 1;
          }
          c_local = (ngx_connection_t *)(*c->send)(c,__ptr,sb.__glibc_reserved[2]);
          ngx_pfree(c->pool,__buf);
          free(__ptr);
        }
      }
    }
  }
  else {
    c_local = (ngx_connection_t *)0xffffffffffffffff;
  }
  return (ssize_t)c_local;
}
"""

REPORT = """
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x<REDACTED> at pc 0x<REDACTED> bp 0x<REDACTED> sp 0x<REDACTED>
WRITE of size <REDACTED> at 0x<REDACTED> thread T0
SCARINESS: <REDACTED> (<REDACTED>-byte-write-heap-buffer-overflow)
    #0 0x<REDACTED> in ngx_sendfile_r /src/harnesses/bld/src/os/unix/ngx_linux_sendfile_chain.c:80:16
    #1 0x<REDACTED> in ngx_linux_sendfile /src/harnesses/bld/src/os/unix/ngx_linux_sendfile_chain.c:305:13
    #2 0x<REDACTED> in ngx_linux_sendfile_chain /src/harnesses/bld/src/os/unix/ngx_linux_sendfile_chain.c:220:17
    #3 0x<REDACTED> in ngx_http_write_filter /src/harnesses/bld/src/http/ngx_http_write_filter_module.c:295:13
    #4 0x<REDACTED> in ngx_http_chunked_body_filter /src/harnesses/bld/src/http/modules/ngx_http_chunked_filter_module.c:115:16
    #5 0x<REDACTED> in ngx_http_gzip_body_filter /src/harnesses/bld/src/http/modules/ngx_http_gzip_filter_module.c:310:16
    #6 0x<REDACTED> in ngx_http_ssi_body_filter /src/harnesses/bld/src/http/modules/ngx_http_ssi_filter_module.c:440:16
    #7 0x<REDACTED> in ngx_http_charset_body_filter /src/harnesses/bld/src/http/modules/ngx_http_charset_filter_module.c
    #8 0x<REDACTED> in ngx_http_addition_body_filter /src/harnesses/bld/src/http/modules/ngx_http_addition_filter_module.c:149:16
    #9 0x<REDACTED> in ngx_http_gunzip_body_filter /src/harnesses/bld/src/http/modules/ngx_http_gunzip_filter_module.c:185:16
    #10 0x<REDACTED> in ngx_http_trailers_filter /src/harnesses/bld/src/http/modules/ngx_http_headers_filter_module.c:264:16
    #11 0x<REDACTED> in ngx_output_chain /src/harnesses/bld/src/core/ngx_output_chain.c:70:20
    #12 0x<REDACTED> in ngx_http_copy_filter /src/harnesses/bld/src/http/ngx_http_copy_filter_module.c:145:10
    #13 0x<REDACTED> in ngx_http_range_singlepart_body /src/harnesses/bld/src/http/modules/ngx_http_range_filter_module.c:846:10
    #14 0x<REDACTED> in ngx_http_range_body_filter /src/harnesses/bld/src/http/modules/ngx_http_range_filter_module.c:674:16
    #15 0x<REDACTED> in ngx_http_output_filter /src/harnesses/bld/src/http/ngx_http_core_module.c:1864:10
    #16 0x<REDACTED> in ngx_http_static_handler /src/harnesses/bld/src/http/modules/ngx_http_static_module.c:281:12
    #17 0x<REDACTED> in ngx_http_core_content_phase /src/harnesses/bld/src/http/ngx_http_core_module.c:1268:10
    #18 0x<REDACTED> in ngx_http_core_run_phases /src/harnesses/bld/src/http/ngx_http_core_module.c:875:14
    #19 0x<REDACTED> in ngx_http_handler /src/harnesses/bld/src/http/ngx_http_core_module.c:858:5
    #20 0x<REDACTED> in ngx_http_internal_redirect /src/harnesses/bld/src/http/ngx_http_core_module.c:2547:5
    #21 0x<REDACTED> in ngx_http_index_handler /src/harnesses/bld/src/http/modules/ngx_http_index_module.c:277:16
    #22 0x<REDACTED> in ngx_http_core_content_phase /src/harnesses/bld/src/http/ngx_http_core_module.c:1268:10
    #23 0x<REDACTED> in ngx_http_core_run_phases /src/harnesses/bld/src/http/ngx_http_core_module.c:875:14
    #24 0x<REDACTED> in ngx_http_handler /src/harnesses/bld/src/http/ngx_http_core_module.c:858:5
    #25 0x<REDACTED> in ngx_http_process_request /src/harnesses/bld/src/http/ngx_http_request.c:2133:5
    #26 0x<REDACTED> in ngx_http_process_request_headers /src/harnesses/bld/src/http/ngx_http_request.c:1529:13
    #27 0x<REDACTED> in ngx_event_process_posted /src/harnesses/bld/src/event/ngx_event_posted.c:34:9
    #28 0x<REDACTED> in LLVMFuzzerTestOneInput /src/harnesses/bld/src/harnesses/pov_harness.cc:325:5
    #29 0x<REDACTED> in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #30 0x<REDACTED> in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #31 0x<REDACTED> in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #32 0x<REDACTED> in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #33 0x<REDACTED> in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x<REDACTED>) (BuildId: 5792732f783158c66fb4f3756458ca24e46e827d)
    #34 0x<REDACTED> in _start (/out/pov_harness+0x<REDACTED>)

DEDUP_TOKEN: ngx_sendfile_r--ngx_linux_sendfile--ngx_linux_sendfile_chain
0x<REDACTED> is located <REDACTED> bytes after <REDACTED>-byte region [0x<REDACTED>,0x<REDACTED>)
allocated by thread T0 here:
    #0 0x<REDACTED> in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:68:3
    #1 0x<REDACTED> in ngx_alloc /src/harnesses/bld/src/os/unix/ngx_alloc.c:22:9
    #2 0x<REDACTED> in ngx_sendfile_r /src/harnesses/bld/src/os/unix/ngx_linux_sendfile_chain.c:73:11
    #3 0x<REDACTED> in ngx_linux_sendfile /src/harnesses/bld/src/os/unix/ngx_linux_sendfile_chain.c:305:13
    #4 0x<REDACTED> in ngx_linux_sendfile_chain /src/harnesses/bld/src/os/unix/ngx_linux_sendfile_chain.c:220:17
    #5 0x<REDACTED> in ngx_http_write_filter /src/harnesses/bld/src/http/ngx_http_write_filter_module.c:295:13
    #6 0x<REDACTED> in ngx_http_chunked_body_filter /src/harnesses/bld/src/http/modules/ngx_http_chunked_filter_module.c:115:16
    #7 0x<REDACTED> in ngx_http_gzip_body_filter /src/harnesses/bld/src/http/modules/ngx_http_gzip_filter_module.c:310:16
    #8 0x<REDACTED> in ngx_http_ssi_body_filter /src/harnesses/bld/src/http/modules/ngx_http_ssi_filter_module.c:440:16
    #9 0x<REDACTED> in ngx_http_charset_body_filter /src/harnesses/bld/src/http/modules/ngx_http_charset_filter_module.c
    #10 0x<REDACTED> in ngx_http_addition_body_filter /src/harnesses/bld/src/http/modules/ngx_http_addition_filter_module.c:149:16
    #11 0x<REDACTED> in ngx_http_gunzip_body_filter /src/harnesses/bld/src/http/modules/ngx_http_gunzip_filter_module.c:185:16
    #12 0x<REDACTED> in ngx_http_trailers_filter /src/harnesses/bld/src/http/modules/ngx_http_headers_filter_module.c:264:16
    #13 0x<REDACTED> in ngx_output_chain /src/harnesses/bld/src/core/ngx_output_chain.c:70:20
    #14 0x<REDACTED> in ngx_http_copy_filter /src/harnesses/bld/src/http/ngx_http_copy_filter_module.c:145:10
    #15 0x<REDACTED> in ngx_http_range_singlepart_body /src/harnesses/bld/src/http/modules/ngx_http_range_filter_module.c:846:10
    #16 0x<REDACTED> in ngx_http_range_body_filter /src/harnesses/bld/src/http/modules/ngx_http_range_filter_module.c:674:16
    #17 0x<REDACTED> in ngx_http_output_filter /src/harnesses/bld/src/http/ngx_http_core_module.c:1864:10
    #18 0x<REDACTED> in ngx_http_static_handler /src/harnesses/bld/src/http/modules/ngx_http_static_module.c:281:12
    #19 0x<REDACTED> in ngx_http_core_content_phase /src/harnesses/bld/src/http/ngx_http_core_module.c:1268:10
    #20 0x<REDACTED> in ngx_http_core_run_phases /src/harnesses/bld/src/http/ngx_http_core_module.c:875:14
    #21 0x<REDACTED> in ngx_http_handler /src/harnesses/bld/src/http/ngx_http_core_module.c:858:5
    #22 0x<REDACTED> in ngx_http_internal_redirect /src/harnesses/bld/src/http/ngx_http_core_module.c:2547:5
    #23 0x<REDACTED> in ngx_http_index_handler /src/harnesses/bld/src/http/modules/ngx_http_index_module.c:277:16
    #24 0x<REDACTED> in ngx_http_core_content_phase /src/harnesses/bld/src/http/ngx_http_core_module.c:1268:10
    #25 0x<REDACTED> in ngx_http_core_run_phases /src/harnesses/bld/src/http/ngx_http_core_module.c:875:14
    #26 0x<REDACTED> in ngx_http_handler /src/harnesses/bld/src/http/ngx_http_core_module.c:858:5
    #27 0x<REDACTED> in ngx_http_process_request /src/harnesses/bld/src/http/ngx_http_request.c:2133:5
    #28 0x<REDACTED> in ngx_http_process_request_headers /src/harnesses/bld/src/http/ngx_http_request.c:1529:13
    #29 0x<REDACTED> in ngx_event_process_posted /src/harnesses/bld/src/event/ngx_event_posted.c:34:9
    #30 0x<REDACTED> in LLVMFuzzerTestOneInput /src/harnesses/bld/src/harnesses/pov_harness.cc:325:5
    #31 0x<REDACTED> in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #32 0x<REDACTED> in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #33 0x<REDACTED> in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9

DEDUP_TOKEN: __interceptor_malloc--ngx_alloc--ngx_sendfile_r
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harnesses/bld/src/os/unix/ngx_linux_sendfile_chain.c:80:16 in ngx_sendfile_r
"""

class TestBinaryPatching(unittest.TestCase):
    def test_dec_patch_gen(self):
        fake_program = Program(Path("."), language="c")
        generator = LLMPlanPatchGenerator(fake_program, "claude-3.7-sonnet")

        func = CodeFunction(
            "ngx_sendfile_r",
            0,
            len(GHIDRA_CODE.splitlines()),
            code=GHIDRA_CODE,
        )
        cluster = PoICluster.from_pois([PoI(func)])
        patch = generator.generate_patch(cluster, reports=[REPORT])

if __name__ == "__main__":
    TestBinaryPatching().test_dec_patch_gen()
    pass
