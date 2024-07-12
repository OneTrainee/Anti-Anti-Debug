# 反调试与反反调试专题

## 01 - IsDebuggerPresent

`IsDebuggerPresent()`函数用来检测当前进程是否被调试，可以被认为是最最基础的调试器检测手段。

其函数实现在 `kernelbase.dll`，其简单两行来实现。

```
.text:000000018000E7F0 IsDebuggerPresent proc near         
.text:000000018000E7F0                                         ; DATA XREF: .rdata:00000001801E636B↓o ...
.text:000000018000E7F0                 mov     rax, gs:60h
.text:000000018000E7F9                 movzx   eax, byte ptr [rax+2]
.text:000000018000E7FD                 retn
.text:000000018000E7FD IsDebuggerPresent endp
```

gs在三环指向TEB，TEB+0x60指向PEB；PEB + 0x2指向一个`BeingDebugged`。

```
struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    ····
}
```

### IsDebuggerPresent反制手段 

既然清楚其原理是通过判断PEB的DeingDebugged位，我们通过驱动编写，将这个位置清零即可。

Windows内核中有一个导出但未声明的函数 `PsGetProcessPeb` ，通过该函数获取PEB即可。

```c++
EXTERN_C PPEB PsGetProcessPeb(PEPROCESS Process);
```

修改时切记要附加到该进程，否则会出现内存读写页错误。

![alt text](8a8853edfe0a1b41aad26bad2e341723.png)
