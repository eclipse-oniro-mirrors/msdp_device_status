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
 
#ifndef ANI_BOOMERANG_MANAGER_H
#define ANI_BOOMERANG_MANAGER_H
 
#include <mutex>
#include <string>
#include <map>
 
#include "ohos.multimodalAwareness.metadataBinding.proj.hpp"
#include "ohos.multimodalAwareness.metadataBinding.impl.hpp"
#include "ani_boomerang.h"
#include "taihe/runtime.hpp"
#include "taihe/callback.hpp"
#include "taihe/optional.hpp"
#include "stdexcept"
#include "boomerang_data.h"
#include "boomerang_callback_stub.h"
#include "devicestatus_client.h"
#include "devicestatus_errors.h"
#include "boomerang_manager.h"
#include <dlfcn.h>
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
 
using namespace ::taihe;
#ifndef RET_OK
    #define RET_OK (0)
#endif
 
const std::map<BoomerangErrCode, std::string> MetadataBindingLogInfo = {
    {SUBSCRIBE_FAILED, "Subscribe Failed. Possible causes: 1. Abnormal system capability;"
        "2. IPC communication abnormality; 3. Algorithm loading exception."},
    {UNSUBSCRIBE_FAILED, "Unsubscribe Failed. Possible causes: 1. Abnormal system capability;"
        "2. IPC communication abnormality."},
    {HANDLER_FAILD, "notify metadataBinding event error by Create execution."},
    {ENCODE_FAILED, "encode image error by Create execution"},
    {DECODE_FAILED, "decode image error by Create execution"}
};
 
class AniBoomerangCallback : public BoomerangCallbackStub {
public:
    explicit AniBoomerangCallback() = default;
    virtual ~AniBoomerangCallback() = default;
    bool init(uintptr_t opq = 0);
 
    void OnScreenshotResult(const BoomerangData& screentshotData) override;
    void OnNotifyMetadata(const std::string& metadata) override;
    void EmitOnEvent(const DeviceStatus::BoomerangData* data);
    void EmitOnMetadata(ani_env env, std::string metadata);
    static void EmitOnEncodeImage(ani_env env, std::shared_ptr<OHOS::Media::PixelMap> pixelMap,
        ani_resolver deferred);
 
    ani_vm* vm_ = nullptr;
    ani_env *env_ = nullptr;
    ani_env* envT_ = nullptr;
    ani_object funObject_ = nullptr;
    ani_ref ref_ = nullptr;
    ani_object promise_ = nullptr;
    ani_resolver deferred_ = nullptr;
    bool attach_ = false;
    bool result_ = false;
 
    std::mutex mutex_;
    BoomerangData data_;
    std::string metadata_;
};
 
class AniBoomerang : public AniBoomerangEvent {
public:
    AniBoomerang();
    DISALLOW_COPY_AND_MOVE(AniBoomerang);
    ~AniBoomerang();
    void onMetadata(std::string bundleName, ::taihe::callback_view<void(int32_t info)> callbck, uintptr_t opq);
    void offMetadata(std::string bundleName, ::taihe::optional_view<uintptr_t> opq);
    void notifyMetadataBindingEvent(std::string bundleName, ani_object& promise);
    void submitMetadata(std::string metadata);
    void encodeImage(uintptr_t srcImage, std::string metadata, ani_object& promise);
    void decodeImage(uintptr_t encodedImage, ani_object& promise);
    static std::shared_ptr<AniBoomerang> GetInstance();
    void setDeferred(std::string data);
    void OnScreenshot(int32_t type, int32_t status, bool isOnce);
private:
    bool EncodeImageFunc(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap, const std::string &content,
        std::shared_ptr<OHOS::Media::PixelMap> &resultPixelMap);
    bool DecodeImageFunc(std::shared_ptr<OHOS::Media::PixelMap> &pixelMap, std::string &content);
 
    ani_ref ref_;
    ani_env *env_ = nullptr;
    std::string metadata_;
    inline static std::mutex mutex_;
};
 
#define ANI_BOOMERANG_MGR BoomerangManager::GetInstance()
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif