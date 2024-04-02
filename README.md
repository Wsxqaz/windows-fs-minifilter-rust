# windows-fs-minifilter-rust

this is for the `x86_64-pc-windows-gnu` target

heavily inspo'd by these [MS driver samples](https://github.com/microsoft/Windows-driver-samples/tree/main/filesys/miniFilter)

## prerequisites

### build

### target

- install Windows SDK from [here](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
-- we need `certmgr`, `MakeCert`, and `signtool` from the SDK
- install DbgView from [sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)

## submodules

- bindgen - generate winapi bindings via windows-bindgen
- filter - the minifilter driver

## setup

the sample filter is a minifilter driver, so you'll need to enable test signing to load it

```powershell
bcdedit /set testsigning on
```

also the example logs via `DbgPrint`, so you'll need to enable debug output

```powershell
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter"; New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" -Name DEFAULT -Value 0xffffffff -PropertyType DWORD -Force
```

reboot. you should see some text on the desktop saying `Test Mode` if setup correctly

## bindgen

note: this is a one-time setup, the bindings are already generated

```
cd bindgen
cargo run
```
output bindings to `./filter/bindings.rs`

## filter

```
cargo --release 2>&1
```

## install filter

1. copy `./filter/target/x86_64-pc-windows-gnu/release/filter.dll`
2. create the service in the registry
```powershell
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Name "DependOnService" -Value "FltMgr" -PropertyType EXPANDSTRING -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Name "Description" -Value "RustFilter" -PropertyType STRING -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Name "DisplayName" -Value "RustFilter" -PropertyType STRING -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Name "ErrorControl" -Value 1 -PropertyType DWORD -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Name "Group" -Value "FSFilter Activity Monitor" -PropertyType STRING -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Name "ImagePath" -Value "\??\C:\path\to\filter.dll" -PropertyType STRING -Force >> log.txt 2> err.txt # !!set this!!
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Name "Start" -Value 3 -PropertyType DWORD -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter" -Name "Type" -Value 2 -PropertyType DWORD -Force >> log.txt 2> err.txt
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter\Instances" -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter\Instances" -Name "DefaultInstance" -Value "filter" -PropertyType STRING -Force >> log.txt 2> err.txt
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter\Instances\filter" -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter\Instances\filter" -Name "Altitude" -Value "370000" -PropertyType STRING -Force >> log.txt 2> err.txt
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RustFilter\Instances\filter" -Name "Flags" -Value "0" -PropertyType DWORD -Force >> log.txt 2> err.txt
```
4. generate a test certificate and install it (do this once)
```powershell
    & 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\MakeCert.exe' -r -pe -ss PrivateCertStore -n "CN=Contoso.com(Test)" -eku 1.3.6.1.5.5.7.3.3 ContosoTest.cer
    & 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\certmgr.exe' /add .\ContosoTest.cer /s /r localMachine root
```
5. sign the driver 
```powershell
    & 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool' sign /v /fd sha256 /s PrivateCertStore /n "Contoso.com(Test)" /t http://timestamp.digicert.com C:\path\to\filter.dll
```
6. run `fltmc load rustfilter`

## tested on

- Windows Server 2022


## the real heroes

- https://github.com/microsoft/windows-rs
- https://myworks2012.wordpress.com/2012/10/07/how-to-compile-windows-driver-using-mingw-gcc/
- https://not-matthias.github.io/posts/kernel-driver-with-rust/
- https://github.com/StephanvanSchaik/windows-kernel-rs
