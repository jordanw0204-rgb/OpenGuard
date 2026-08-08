#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

namespace {
const GUID kKernelProcessProvider = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
TRACEHANDLE g_session = 0;
TRACEHANDLE g_trace = 0;
std::wstring g_session_name;
std::vector<BYTE> g_properties_buffer;

EVENT_TRACE_PROPERTIES* Properties() {
    return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(g_properties_buffer.data());
}

ULONG EventProcessId(PEVENT_RECORD event) {
    ULONG size = 0;
    if (TdhGetEventInformation(event, 0, nullptr, nullptr, &size) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> storage(size);
        auto info = reinterpret_cast<PTRACE_EVENT_INFO>(storage.data());
        if (TdhGetEventInformation(event, 0, nullptr, info, &size) == ERROR_SUCCESS) {
            for (ULONG index = 0; index < info->TopLevelPropertyCount; ++index) {
                auto& property = info->EventPropertyInfoArray[index];
                auto name = reinterpret_cast<PCWSTR>(storage.data() + property.NameOffset);
                if (_wcsicmp(name, L"ProcessID") != 0 && _wcsicmp(name, L"ProcessId") != 0) {
                    continue;
                }
                PROPERTY_DATA_DESCRIPTOR descriptor{};
                descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
                descriptor.ArrayIndex = ULONG_MAX;
                ULONG value_size = 0;
                if (TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &value_size) != ERROR_SUCCESS ||
                    value_size == 0 || value_size > sizeof(ULONGLONG)) {
                    break;
                }
                ULONGLONG value = 0;
                if (TdhGetProperty(event, 0, nullptr, 1, &descriptor, value_size,
                                   reinterpret_cast<PBYTE>(&value)) == ERROR_SUCCESS) {
                    return static_cast<ULONG>(value);
                }
            }
        }
    }
    return event->EventHeader.ProcessId;
}

std::vector<BYTE> EventProperty(PEVENT_RECORD event, const wchar_t* requested_name) {
    ULONG info_size = 0;
    if (TdhGetEventInformation(event, 0, nullptr, nullptr, &info_size) != ERROR_INSUFFICIENT_BUFFER) {
        return {};
    }
    std::vector<BYTE> info_storage(info_size);
    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(info_storage.data());
    if (TdhGetEventInformation(event, 0, nullptr, info, &info_size) != ERROR_SUCCESS) {
        return {};
    }
    for (ULONG index = 0; index < info->TopLevelPropertyCount; ++index) {
        auto& property = info->EventPropertyInfoArray[index];
        auto name = reinterpret_cast<PCWSTR>(info_storage.data() + property.NameOffset);
        if (_wcsicmp(name, requested_name) != 0) {
            continue;
        }
        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = ULONG_MAX;
        ULONG value_size = 0;
        if (TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &value_size) != ERROR_SUCCESS ||
            value_size == 0 || value_size > 64 * 1024) {
            return {};
        }
        std::vector<BYTE> value(value_size);
        if (TdhGetProperty(event, 0, nullptr, 1, &descriptor, value_size, value.data()) ==
            ERROR_SUCCESS) {
            return value;
        }
    }
    return {};
}

ULONG EventUlong(PEVENT_RECORD event, const wchar_t* name) {
    const auto value = EventProperty(event, name);
    if (value.size() >= sizeof(ULONG)) {
        ULONG result = 0;
        memcpy(&result, value.data(), sizeof(result));
        return result;
    }
    return 0;
}

std::string Utf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(),
                        size, nullptr, nullptr);
    return result;
}

std::string EventText(PEVENT_RECORD event, const wchar_t* name) {
    const auto value = EventProperty(event, name);
    if (value.empty()) {
        return {};
    }
    if (value.size() >= sizeof(wchar_t) && value.size() % sizeof(wchar_t) == 0) {
        const auto wide = reinterpret_cast<const wchar_t*>(value.data());
        const size_t count = value.size() / sizeof(wchar_t);
        size_t length = 0;
        while (length < count && wide[length] != L'\0') {
            ++length;
        }
        const std::string decoded = Utf8(std::wstring(wide, length));
        if (!decoded.empty()) {
            return decoded;
        }
    }
    const auto text = reinterpret_cast<const char*>(value.data());
    size_t length = 0;
    while (length < value.size() && text[length] != '\0') {
        ++length;
    }
    return std::string(text, length);
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
        switch (character) {
            case '\\': output << "\\\\"; break;
            case '"': output << "\\\""; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20) {
                    const char hex[] = "0123456789abcdef";
                    output << "\\u00" << hex[character >> 4] << hex[character & 0xf];
                } else {
                    output << character;
                }
        }
    }
    return output.str();
}

VOID WINAPI OnEvent(PEVENT_RECORD event) {
    if (!IsEqualGUID(event->EventHeader.ProviderId, kKernelProcessProvider)) {
        return;
    }
    const USHORT id = event->EventHeader.EventDescriptor.Id;
    if (id != 1 && id != 2) {
        return;
    }
    const ULONG pid = EventProcessId(event);
    const ULONG parent_pid = id == 1 ? EventUlong(event, L"ParentProcessID") : 0;
    const std::string image = id == 1 ? EventText(event, L"ImageName") : std::string{};
    const std::string command_line = id == 1 ? EventText(event, L"CommandLine") : std::string{};
    std::cout << "{\"type\":\"" << (id == 1 ? "start" : "stop")
              << "\",\"pid\":" << pid << ",\"parent_pid\":" << parent_pid
              << ",\"image\":\"" << JsonEscape(image) << "\",\"command_line\":\""
              << JsonEscape(command_line) << "\",\"event_id\":" << id << "}" << std::endl;
}

void StopTraceSession() {
    if (g_trace && g_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_trace);
        g_trace = 0;
    }
    if (g_session) {
        EnableTraceEx2(g_session, &kKernelProcessProvider, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                       TRACE_LEVEL_NONE, 0, 0, 0, nullptr);
        ControlTraceW(g_session, g_session_name.c_str(), Properties(), EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
    }
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT ||
        signal == CTRL_SHUTDOWN_EVENT) {
        StopTraceSession();
        return TRUE;
    }
    return FALSE;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    bool probe = false;
    DWORD parent_pid = 0;
    std::wstring stop_event_name;
    for (int index = 1; index < argc; ++index) {
        if (_wcsicmp(argv[index], L"--probe") == 0) {
            probe = true;
        } else if (_wcsicmp(argv[index], L"--stop-event") == 0 && index + 1 < argc) {
            stop_event_name = argv[++index];
        } else if (_wcsicmp(argv[index], L"--parent-pid") == 0 && index + 1 < argc) {
            wchar_t* end = nullptr;
            const unsigned long parsed = std::wcstoul(argv[++index], &end, 10);
            if (end && *end == L'\0' && parsed <= MAXDWORD) {
                parent_pid = static_cast<DWORD>(parsed);
            }
        }
    }

    g_session_name = L"OpenGuard-KernelProcess-" + std::to_wstring(GetCurrentProcessId());
    const size_t property_size = sizeof(EVENT_TRACE_PROPERTIES) +
                                 (g_session_name.size() + 1) * sizeof(wchar_t);
    g_properties_buffer.assign(property_size, 0);
    auto properties = Properties();
    properties->Wnode.BufferSize = static_cast<ULONG>(property_size);
    properties->Wnode.ClientContext = 1;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_session, g_session_name.c_str(), properties);
    if (status != ERROR_SUCCESS) {
        std::cerr << "{\"status\":\"unavailable\",\"stage\":\"StartTraceW\",\"win32_error\":"
                  << status << "}" << std::endl;
        return 2;
    }
    status = EnableTraceEx2(g_session, &kKernelProcessProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0x10, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "{\"status\":\"unavailable\",\"stage\":\"EnableTraceEx2\",\"win32_error\":"
                  << status << "}" << std::endl;
        StopTraceSession();
        return 3;
    }

    if (probe) {
        std::cout << "{\"status\":\"available\",\"provider\":\"Microsoft-Windows-Kernel-Process\"}"
                  << std::endl;
        StopTraceSession();
        return 0;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(g_session_name.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = OnEvent;
    g_trace = OpenTraceW(&logfile);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) {
        status = GetLastError();
        std::cerr << "{\"status\":\"unavailable\",\"stage\":\"OpenTraceW\",\"win32_error\":"
                  << status << "}" << std::endl;
        StopTraceSession();
        return 4;
    }
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    std::vector<HANDLE> shutdown_handles;
    if (!stop_event_name.empty()) {
        if (HANDLE stop_event = OpenEventW(SYNCHRONIZE, FALSE, stop_event_name.c_str())) {
            shutdown_handles.push_back(stop_event);
        }
    }
    if (parent_pid != 0) {
        if (HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, parent_pid)) {
            shutdown_handles.push_back(parent);
        } else {
            std::cerr << "{\"warning\":\"parent_watch_unavailable\",\"win32_error\":"
                      << GetLastError() << "}" << std::endl;
        }
    }
    if (!shutdown_handles.empty()) {
        std::thread([handles = std::move(shutdown_handles)]() {
            WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE,
                                   INFINITE);
            StopTraceSession();
            for (HANDLE handle : handles) {
                CloseHandle(handle);
            }
        }).detach();
    }
    std::cout << "{\"status\":\"running\",\"provider\":\"Microsoft-Windows-Kernel-Process\"}"
              << std::endl;
    status = ProcessTrace(&g_trace, 1, nullptr, nullptr);
    StopTraceSession();
    return status == ERROR_SUCCESS || status == ERROR_CANCELLED ? 0 : 5;
}
