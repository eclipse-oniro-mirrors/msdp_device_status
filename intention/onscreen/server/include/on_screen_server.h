/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ON_SCREEN_SERVER_H
#define ON_SCREEN_SERVER_H

#include <mutex>
#include <map>

#include "i_on_screen_algorithm.h"
#include "i_plugin.h"
#include "on_screen_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
struct OnScreenAlgorithmHandle {
    OnScreenAlgorithmHandle() : handle(nullptr), pAlgorithm(nullptr), create(nullptr), destroy(nullptr) {}
    ~OnScreenAlgorithmHandle();
    void Clear();
    void* handle = nullptr;
    IOnScreenAlgorithm* pAlgorithm = nullptr;
    IOnScreenAlgorithm* (*create)();
    void (*destroy)(const IOnScreenAlgorithm*);
};

class OnScreenServer {
public:
    OnScreenServer() = default;
    virtual ~OnScreenServer();
    int32_t GetPageContent(const CallingContext &context, const ContentOption &option, PageContent &pageContent);
    int32_t SendControlEvent(const CallingContext &context, const ControlEvent &event);
    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args);
    int32_t RegisterScreenEventCallback(const CallingContext& context, int32_t windowId, const std::string& event,
        const sptr<IRemoteOnScreenCallback>& callback);
    int32_t UnregisterScreenEventCallback(const CallingContext& context, int32_t windowId, const std::string& event,
        const sptr<IRemoteOnScreenCallback>& callback);
    int32_t IsParallelFeatureEnabled(const CallingContext& context, int32_t windowId, int32_t& outStatus);
    int32_t ListenLiveBroadcast();
    int32_t GetLiveStatus();

    int32_t RegisterAwarenessCallback(const CallingContext &context, const AwarenessCap& cap,
        const sptr<IRemoteOnScreenCallback>& callback, const AwarenessOptions& option);
    int32_t UnregisterAwarenessCallback(const CallingContext &context, const AwarenessCap& cap,
        const sptr<IRemoteOnScreenCallback>& callback);
    int32_t Trigger(const CallingContext &context, const AwarenessCap& cap, const AwarenessOptions& option,
        OnscreenAwarenessInfo& info);

private:
    int32_t LoadAlgoLib();
    int32_t UnloadAlgoLib();
    int32_t ConnectAlgoLib();
    bool CheckPermission(const CallingContext &context, const std::string &permission);
    bool IsSystemCalling(const CallingContext &context);
    bool IsWhitelistAppCalling(const CallingContext &context);
    bool GetAppIdentifier(const std::string& bundleName, int32_t userId, std::string& appIdentifier);
    bool IsSystemServiceCalling(const CallingContext &context);
    bool CheckDeviceType();
    bool SaveCallbackInfo(const sptr<IRemoteOnScreenCallback>& callback, const AwarenessCap& cap);
    std::vector<std::string> GetUnusedCap(const AwarenessCap& cap);
    bool RemoveCallbackInfo(const sptr<IRemoteOnScreenCallback>& callback, const AwarenessCap& cap);

    std::map<sptr<IRemoteOnScreenCallback>, std::set<std::string>> callbackInfo_;
    std::map<uint32_t, std::string> bundleNames_;
    OnScreenAlgorithmHandle handle_;
    std::mutex mtx_;
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ON_SCREEN_SERVER_H