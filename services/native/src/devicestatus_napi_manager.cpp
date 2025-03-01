/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
 
#include "devicestatus_napi_manager.h"
#include <dlfcn.h>
#include <cstdlib>
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangAlgoManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void* BoomerangAlgoManager::boomerangAlgoHandle_ = nullptr;
EncodeImageFunc BoomerangAlgoManager::boomerangAlgoEncodeImageHandle_ = nullptr;
DecodeImageFunc BoomerangAlgoManager::boomerangAlgoDecodeImageHandle_ = nullptr;

const std::string BOOMERANG_ALGO_SO_PATH = "system/lib64/libmsdp_boomerang_algo.z.so";

bool BoomerangAlgoManager::EncodeImage(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content,
                                       std::shared_ptr<Media::PixelMap> &resultPixelMap)
{
    FI_HILOGI("Boomerang Algo Encode Load");
    char realPath[PATH_MAX] = {};
    if (realpath(BOOMERANG_ALGO_SO_PATH.c_str(), realPath) == nullptr) {
        FI_HILOGE("Path is error, path is %{private}s", BOOMERANG_ALGO_SO_PATH.c_str());
        return false;
    }
    if (boomerangAlgoHandle_ == nullptr) {
        boomerangAlgoHandle_ = dlopen(realPath, RTLD_LAZY);
        char *error = nullptr;
        if (((error = dlerror()) != nullptr) || (boomerangAlgoHandle_ == nullptr)) {
            FI_HILOGE("Boomerang Algo Encode Load failed, error: %{public}s", error);
            return false;
        }
    }
    if (boomerangAlgoEncodeImageHandle_ == nullptr) {
        boomerangAlgoEncodeImageHandle_ = reinterpret_cast<EncodeImageFunc>(dlsym(boomerangAlgoHandle_, "EncodeImage"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Boomerang Algo Encode find symbol failed, error: %{public}s", error);
            return false;
        }
    }
    boomerangAlgoEncodeImageHandle_(pixelMap, content, resultPixelMap);
    FI_HILOGI("Boomerang Algo Encode success");
    return true;
}

bool BoomerangAlgoManager::DecodeImage(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content)
{
    FI_HILOGI("Boomerang Algo Decode Load");
    char realPath[PATH_MAX] = {};
    if (realpath(BOOMERANG_ALGO_SO_PATH.c_str(), realPath) == nullptr) {
        FI_HILOGE("Path is error, path is %{private}s", BOOMERANG_ALGO_SO_PATH.c_str());
        return false;
    }
    if (boomerangAlgoHandle_ == nullptr) {
        boomerangAlgoHandle_ = dlopen(realPath, RTLD_LAZY);
        char *error = nullptr;
        if (((error = dlerror()) != nullptr) || (boomerangAlgoHandle_ == nullptr)) {
            FI_HILOGE("Boomerang Algo Decode Load failed, error: %{public}s", error);
            return false;
        }
    }
    if (boomerangAlgoDecodeImageHandle_ == nullptr) {
        boomerangAlgoDecodeImageHandle_ = reinterpret_cast<DecodeImageFunc>(dlsym(boomerangAlgoHandle_, "DecodeImage"));
        char *error = nullptr;
        if (((error = dlerror()) != nullptr) || (boomerangAlgoDecodeImageHandle_ == nullptr)) {
            FI_HILOGE("Boomerang Algo Decode find symbol failed, error: %{public}s", error);
            return false;
        }
    }
    boomerangAlgoDecodeImageHandle_(pixelMap, content);
    FI_HILOGI("Boomerang Algo Decode success");
    return true;
}

BoomerangAlgoManager::~BoomerangAlgoManager()
{
    FI_HILOGI("Boomerang Algo Unload");
    if (boomerangAlgoHandle_ != nullptr) {
        dlclose(boomerangAlgoHandle_);
        boomerangAlgoHandle_ = nullptr;
        FI_HILOGI("Remove boomerangAlgoHandle_");
    }
    boomerangAlgoEncodeImageHandle_ = nullptr;
    boomerangAlgoDecodeImageHandle_ = nullptr;
}

void BoomerangAlgoImpl::EncodeImage(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content,
                                    std::shared_ptr<Media::PixelMap> &resultPixelMap)
{
    FI_HILOGI("Boomerang Enter BoomerangAlgoImpl Encode Image");
    if (BoomerangAlgoManager::EncodeImage(pixelMap, content, resultPixelMap) != true) {
        resultPixelMap = pixelMap;
        FI_HILOGE("BoomerangAlgoImpl Encode fail");
    }
    FI_HILOGI("BoomerangAlgoImpl Encode Success");
}

void BoomerangAlgoImpl::DecodeImage(std::shared_ptr<Media::PixelMap> &pixelMap, std::string &content)
{
    BoomerangAlgoManager::DecodeImage(pixelMap, content);
    return;
}
}   // namespace DeviceStatus
}   // namespace Msdp
}   // namespace OHOS