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

#ifndef DEVICESTATUS_NAPI_H
#define DEVICESTATUS_NAPI_H

#include <map>
#include <tuple>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include <uv.h>

#include "boomerang_callback_stub.h"
#include "boomerang_event.h"
#include "boomerang_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangCallback : public BoomerangCallbackStub {
public:
    explicit BoomerangCallback(napi_env env, napi_deferred deferred) : env_(env), deferred_(deferred) {}
    virtual ~BoomerangCallback() {};
    void OnScreenshotResult(const BoomerangData& data) override;
    void OnNotifyMetadata(const std::string& metadata) override;
    void OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap) override;
    static void EmitOnEvent(BoomerangData* data);
    static void EmitOnMetadata(napi_env env, std::string metadata, napi_deferred deferred);
    static void EmitOnEncodeImage(napi_env env, std::shared_ptr<Media::PixelMap> pixelMap,
        napi_deferred deferred);
private:
    napi_env env_ { nullptr };
    napi_deferred deferred_;
    std::mutex mutex_;
    BoomerangData data_;
    std::string metadata_;
    std::shared_ptr<Media::PixelMap> pixelMap_;
};

struct AsyncContext {
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_handle_scope scope;
    sptr<IRemoteBoomerangCallback> callback = nullptr;
    std::string bundleName;
    std::string metadata;
    std::shared_ptr<Media::PixelMap> pixelMap;
    int32_t result;
};

class BoomerangNapi : public BoomerangEvent {
public:
    explicit BoomerangNapi(napi_env env);
    virtual ~BoomerangNapi();

    static napi_value Init(napi_env env, napi_value exports);

    static bool InitNapiObject(napi_env env, napi_callback_info info);
    static napi_value Register(napi_env env, napi_callback_info info);
    static napi_value UnRegister(napi_env env, napi_callback_info info);
    static napi_value NotifyMetadataBindingEvent(napi_env env, napi_callback_info info);
    static napi_value SubmitMetadata(napi_env env, napi_callback_info info);
    static napi_value BoomerangEncodeImage(napi_env env, napi_callback_info info);
    static napi_value DecodeImage(napi_env env, napi_callback_info info);
    static napi_value SubscribeMeatadataCallback(napi_env env, napi_callback_info info, napi_value handler,
        int32_t type, std::string bundleName);
    static int32_t ConvertTypeToInt(const std::string &type);
    void OnScreenshot(int32_t type, int32_t value, bool isOnce);
    void OnMetadata(napi_env env, std::string metadata, bool isOnce, napi_deferred deferred);
    void OnEncodeImage(napi_env env, std::shared_ptr<Media::PixelMap> pixelMap, napi_deferred deferred);
    static BoomerangNapi* GetDeviceStatusNapi();
    static std::map<int32_t, sptr<IRemoteBoomerangCallback>> callbacks_;
    static std::string metadata_;

private:
    static bool CheckArguments(napi_env env, napi_callback_info info, int32_t validataType);
    static bool IsSameHandle(napi_env env, napi_value handle, napi_ref ref);
    static bool CreateMetadataExecution(napi_env env, AsyncContext *asyncContext, std::string typeInt,
        sptr<IRemoteBoomerangCallback> callbacks);
    static void NotifyMetadataExecuteCB(napi_env env, void* data);
    static void NotifyMetadataCompleteCB(napi_env env, napi_status status, void* data);
    static bool CreateEncodeImageExecution(napi_env env, AsyncContext *asyncContext,
        std::string metadata, std::shared_ptr<Media::PixelMap> pixelMap, sptr<IRemoteBoomerangCallback> callback);
    static void EncodeImageExecuteCB(napi_env env, void* data);
    static void EncodeImageCompleteCB(napi_env env, napi_status status, void* data);
    static bool CreateDecodeImageExecution(napi_env env, AsyncContext *asyncContext,
        std::shared_ptr<Media::PixelMap> pixelMap, sptr<IRemoteBoomerangCallback> callback);
    static void DecodeImageExecuteCB(napi_env env, void* data);
    static void DecodeImageCompleteCB(napi_env env, napi_status status, void* data);
    static void ProcessErrorResult(napi_env env, int32_t result, int32_t code, AsyncContext* asyncContext);
    static napi_ref boomerangValueRef_;
    napi_env env_ { nullptr };
    inline static std::mutex mutex_;
    inline static std::mutex notifyMutex_;
    inline static std::mutex encodeMutex_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_NAPI_H
