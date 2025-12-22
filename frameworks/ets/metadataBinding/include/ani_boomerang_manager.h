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

#include <dlfcn.h>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>

#include "ani_boomerang.h"
#include "boomerang_callback_stub.h"
#include "boomerang_data.h"
#include "boomerang_manager.h"
#include "devicestatus_client.h"
#include "devicestatus_errors.h"
#include "ohos.multimodalAwareness.metadataBinding.proj.hpp"
#include "ohos.multimodalAwareness.metadataBinding.impl.hpp"
#include "taihe/callback.hpp"
#include "taihe/optional.hpp"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

using namespace ::taihe;
#ifndef RET_OK
    #define RET_OK (0)
#endif

#ifndef RET_ERR
    #define RET_ERR (-1)
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
    bool Init(uintptr_t opq = 0);

    void OnScreenshotResult(const BoomerangData& screenshotData) override;
    void OnNotifyMetadata(const std::string& metadata) override;
    void OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap) override;
    bool GetMetadata(std::string &metadata);
    bool GetEncodeImage(std::shared_ptr<Media::PixelMap> image);
    static ani_vm* vm_;
    ani_env *env_ = nullptr;
    ani_env* envT_ = nullptr;
    ani_object funObject_ = nullptr;
    ani_ref ref_ = nullptr;
    ani_object promise_ = nullptr;
    ani_resolver deferred_ = nullptr;
    bool attach_ = false;
    bool result_ = false;

    std::mutex mutex_;
    std::mutex notifyMutex_;
    std::mutex imageMutex_;
    BoomerangData data_;
    std::string metadata_;
    std::string decodeImage_;
    std::shared_ptr<Media::PixelMap> pixelMap_ = nullptr;
    bool notifyFlag_ = false;
    bool onEncodeImageFlag_ = false;
};

class AniBoomerang : public AniBoomerangEvent {
public:
    AniBoomerang();
    DISALLOW_COPY_AND_MOVE(AniBoomerang);
    ~AniBoomerang();
    void OnMetadata(const std::string &bundleName, ::taihe::callback_view<void(int32_t info)> callback, uintptr_t opq);
    void OffMetadata(const std::string &bundleName, ::taihe::optional_view<uintptr_t> opq);
    std::string NotifyMetadataBindingEvent(const std::string &bundleName);
    void SubmitMetadata(const std::string &metadata);
    ani_object EncodeImage(uintptr_t srcImage, const std::string &metadata);
    std::string DecodeImage(uintptr_t encodedImage);
    static std::shared_ptr<AniBoomerang> GetInstance();
    void OnScreenshot(int32_t type, int32_t status, bool isOnce);
    void OnEncodeImage(ani_env *env, std::shared_ptr<Media::PixelMap> pixelMap, ani_resolver deferred);
    void ProcessErrorResult(ani_env *env, int32_t result, int32_t code, ani_resolver deferred);

public:
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
