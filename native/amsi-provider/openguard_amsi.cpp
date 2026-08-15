#include <amsi.h>
#include <objbase.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <new>
#include <string>
#include <vector>

namespace {
constexpr CLSID kProviderClsid = {
    0x5f39a65e, 0x3d26, 0x4d78, {0x92, 0x3d, 0x38, 0x48, 0x69, 0x5a, 0xd0, 0x61}};
constexpr ULONGLONG kMaximumContentBytes = 16ULL * 1024ULL * 1024ULL;
std::atomic<long> g_objects{0};

bool Contains(const std::string& text, const char* needle) {
    return text.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& text, std::initializer_list<const char*> needles) {
    return std::any_of(needles.begin(), needles.end(), [&](const char* needle) {
        return Contains(text, needle);
    });
}

std::string Lowercase(const std::vector<std::uint8_t>& content) {
    std::string text(content.begin(), content.end());
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return text;
}

AMSI_RESULT Assess(const std::vector<std::uint8_t>& content) {
    const std::string text = Lowercase(content);
    if (Contains(text, "eicar-standard-antivirus-test-file") ||
        Contains(text, "openguard_signed_content_test_marker_2026")) {
        return AMSI_RESULT_DETECTED;
    }

    const bool encoded = ContainsAny(text, {"-encodedcommand", "frombase64string("});
    const bool dynamic = ContainsAny(text, {"invoke-expression", "iex(", "downloadstring("});
    const bool injection = ContainsAny(text, {"writeprocessmemory", "createremotethread"}) &&
                           ContainsAny(text, {"virtualallocex", "ntallocatevirtualmemory"});
    const bool browser = ContainsAny(text, {"\\google\\chrome\\user data", "login data",
                                                 "cookies.sqlite", "network\\cookies"}) &&
                         ContainsAny(text, {"cryptunprotectdata", "os_crypt.encrypted_key"}) &&
                         ContainsAny(text, {"sqlite3_open", "copyfile"});
    const bool credential_dump = Contains(text, "lsass") &&
                                 ContainsAny(text, {"minidumpwritedump", "comsvcs.dll", "sekurlsa"});
    if (browser || credential_dump || (encoded && dynamic && injection)) {
        return static_cast<AMSI_RESULT>(31'000);
    }
    if ((encoded && dynamic) || injection) {
        return static_cast<AMSI_RESULT>(20'000);
    }
    return AMSI_RESULT_CLEAN;
}

class Provider final : public IAntimalwareProvider {
  public:
    Provider() { g_objects.fetch_add(1, std::memory_order_relaxed); }
    ~Provider() { g_objects.fetch_sub(1, std::memory_order_relaxed); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (iid == IID_IUnknown || iid == __uuidof(IAntimalwareProvider)) {
            *object = static_cast<IAntimalwareProvider*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }

    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG remaining = --references_;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) override {
        if (stream == nullptr || result == nullptr) {
            return E_POINTER;
        }
        *result = AMSI_RESULT_NOT_DETECTED;
        ULONGLONG size = 0;
        ULONG received = 0;
        HRESULT status = stream->GetAttribute(
            AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(size), reinterpret_cast<PBYTE>(&size), &received);
        if (FAILED(status) || received != sizeof(size) || size > kMaximumContentBytes) {
            return FAILED(status) ? status : S_OK;
        }
        std::vector<std::uint8_t> content(static_cast<std::size_t>(size));
        ULONGLONG offset = 0;
        while (offset < size) {
            const ULONG request = static_cast<ULONG>(
                std::min<ULONGLONG>(size - offset, 1024ULL * 1024ULL));
            ULONG read = 0;
            status = stream->Read(offset, request, content.data() + offset, &read);
            if (FAILED(status)) {
                return status;
            }
            if (read == 0) {
                break;
            }
            offset += read;
        }
        content.resize(static_cast<std::size_t>(offset));
        *result = Assess(content);
        return S_OK;
    }

    void STDMETHODCALLTYPE CloseSession(ULONGLONG) override {}

    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* displayName) override {
        if (displayName == nullptr) {
            return E_POINTER;
        }
        constexpr wchar_t kName[] = L"OpenGuard Antimalware Provider";
        const std::size_t bytes = sizeof(kName);
        *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
        if (*displayName == nullptr) {
            return E_OUTOFMEMORY;
        }
        memcpy(*displayName, kName, bytes);
        return S_OK;
    }

  private:
    std::atomic<ULONG> references_{1};
};

class Factory final : public IClassFactory {
  public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (iid == IID_IUnknown || iid == IID_IClassFactory) {
            *object = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return ++references_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG remaining = --references_;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** object) override {
        if (outer != nullptr) {
            return CLASS_E_NOAGGREGATION;
        }
        Provider* provider = new (std::nothrow) Provider();
        if (provider == nullptr) {
            return E_OUTOFMEMORY;
        }
        const HRESULT status = provider->QueryInterface(iid, object);
        provider->Release();
        return status;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) {
            g_objects.fetch_add(1, std::memory_order_relaxed);
        } else {
            g_objects.fetch_sub(1, std::memory_order_relaxed);
        }
        return S_OK;
    }

  private:
    std::atomic<ULONG> references_{1};
};
}  // namespace

STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, LPVOID* object) {
    if (clsid != kProviderClsid) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    Factory* factory = new (std::nothrow) Factory();
    if (factory == nullptr) {
        return E_OUTOFMEMORY;
    }
    const HRESULT status = factory->QueryInterface(iid, object);
    factory->Release();
    return status;
}

STDAPI DllCanUnloadNow() {
    return g_objects.load(std::memory_order_relaxed) == 0 ? S_OK : S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
