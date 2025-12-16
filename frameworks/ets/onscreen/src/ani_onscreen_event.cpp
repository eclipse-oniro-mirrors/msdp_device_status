/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <variant>
#include "ani_onscreen_event.h"
#include "devicestatus_define.h"
#include "pixel_map_taihe_ani.h"

#undef LOG_TAG
#define LOG_TAG "AniOnscreenEvent"

namespace ANI::MultimodalAwareness {
using namespace taihe;
using namespace OHOS;
using namespace OHOS::Msdp;
using namespace OHOS::Msdp::DeviceStatus;
using namespace ohos::multimodalAwareness::onScreen;

static std::string ANIUtils_ANIStringToStdString(ani_env *env, ani_string ani_str)
{
    ani_size sz {};
    env->String_GetUTF8Size(ani_str, &sz);
    std::string result(sz + 1, 0);
    env->String_GetUTF8(ani_str, result.data(), result.size(), &sz);
    result.resize(sz);
    return result;
}

static ani_array ANIUtils_StdVectorToANIArray(ani_env *env, std::vector<std::string> arg)
{
    ani_array array;
    env->Array_New(arg.size(), nullptr, &array);
    ani_size index = 0;
    for (auto num : arg) {
        ani_object boxedNumber;
        ani_string value = nullptr;
        env->String_NewUTF8(num.c_str(), num.size(), &value);
        boxedNumber = reinterpret_cast<ani_object>(value);
        env->Array_Set(array, index, boxedNumber);
        index++;
    }
    return array;
}

static ani_array ANIUtils_StdVectorImageIdToANIArray(ani_env *env,
    std::vector<OnScreen::AwarenessInfoImageId> arg)
{
    ani_array array;
    env->Array_New(arg.size(), nullptr, &array);
    ani_size index = 0;
    for (auto num : arg) {
        ani_object boxedNumber;
        ani_string value = nullptr;
        const std::string &val = "compId: " + num.compId + " arkDataId: " + num.arkDataId;
        env->String_NewUTF8(val.c_str(), val.size(), &value);
        boxedNumber = reinterpret_cast<ani_object>(value);
        env->Array_Set(array, index, boxedNumber);
        index++;
    }
    return array;
}

static std::vector<std::string> ANIUtils_ANIArrayToStdVector(ani_env *env, ani_array strArray)
{
    ani_size sizeResult = 0;
    env->Array_GetLength(strArray, &sizeResult);
    ani_ref result = nullptr;
    std::vector<std::string> stringVector;
    for (ani_size i = 0; i < sizeResult; i++) {
        env->Array_Get(strArray, i, &result);
        auto stringContent = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(result));
        stringVector.push_back(stringContent);
    }
    return stringVector;
}

bool AniOnscreenEvent::ValueObjToAni(const OnScreen::ValueObj valueObj, ani_object &aniValue)
{
    ani_env *env = taihe::get_env();
    CHKCF(env != nullptr, "ani_env is nullptr");
    CALL_INFO_TRACE;
    std::visit([env, &aniValue](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, bool>) {
            ani_boolean value = arg;
            aniValue = reinterpret_cast<ani_object>(value);
            FI_HILOGI("create boolean is %{public}d", arg);
            return true;
        } else if constexpr (std::is_same_v<T, int32_t>) {
            ani_int value = static_cast<ani_int>(arg);
            ani_variable variable {};
            CHKCF(env->Variable_SetValue_Int(variable, value) == ANI_OK, "create int32 failed");
            aniValue = reinterpret_cast<ani_object>(variable);
            return true;
        } else if constexpr (std::is_same_v<T, int64_t>) {
            ani_long value = static_cast<ani_long>(arg);
            ani_variable variable {};
            CHKCF(env->Variable_SetValue_Long(variable, value) == ANI_OK, "create int64_t failed");
            aniValue = reinterpret_cast<ani_object>(variable);
            return true;
        } else if constexpr (std::is_same_v<T, std::string>) {
            ani_string value = nullptr;
            const std::string &val = arg;
            CHKCF(env->String_NewUTF8(val.c_str(), val.size(), &value) == ANI_OK, "create str failed");
            aniValue = reinterpret_cast<ani_object>(value);
            return true;
        } else if constexpr (std::is_same_v<T, OnScreen::AwarenessInfoPageLink>) {
            ani_string value = nullptr;
            const std::string &val = "httpLink: " + arg.httpLink + " deepLink: " + arg.deepLink;
            CHKCF(env->String_NewUTF8(val.c_str(), val.size(), &value) == ANI_OK, "create str failed");
            aniValue = reinterpret_cast<ani_object>(value);
            return true;
        } else if constexpr (std::is_same_v<T, std::shared_ptr<OHOS::Media::PixelMap>>) {
            aniValue = OHOS::Media::PixelMapTaiheAni::CreateEtsPixelMap(env, arg);
            CHKCF(aniValue != nullptr, "create pixel map failed");
            return true;
        } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            aniValue = reinterpret_cast<ani_object>(ANIUtils_StdVectorToANIArray(env, arg));
            return true;
        } else if constexpr (std::is_same_v<T, std::vector<OnScreen::AwarenessInfoImageId>>) {
            aniValue = reinterpret_cast<ani_object>(ANIUtils_StdVectorImageIdToANIArray(env, arg));
            return true;
        }
        }, valueObj);
    return true;
}

bool AniOnscreenEvent::AniToValueObj(const ani_object aniValue, OnScreen::ValueObj &valueObj)
{
    ani_env *env = taihe::get_env();
    CHKCF(env != nullptr, "ani_env is nullptr");
    ani_boolean res;
    ani_class optionClass {};
    env->FindClass("std.core.Boolean", &optionClass);
    CHKCF(env->Object_InstanceOf(aniValue, optionClass, &res) == ANI_OK, "create boolean failed");
    if (res) {
        ani_boolean value;
        CHKCF(env->Object_CallMethodByName_Boolean(aniValue, "toBoolean", ":b", &value) == ANI_OK,
            "create boolean failed");
        valueObj = static_cast<bool>(value);
        return true;
    }
    env->FindClass("std.core.Int", &optionClass);
    CHKCF(env->Object_InstanceOf(aniValue, optionClass, &res) == ANI_OK, "create int failed");
    if (res) {
        ani_int value;
        CHKCF(env->Object_CallMethodByName_Int(aniValue, "toInt", ":i", &value) == ANI_OK, "create int failed");
        valueObj = static_cast<int32_t>(value);
        return true;
    }
    env->FindClass("std.core.Long", &optionClass);
    CHKCF(env->Object_InstanceOf(aniValue, optionClass, &res) == ANI_OK, "create long failed");
    if (res) {
        ani_long value;
        CHKCF(env->Object_CallMethodByName_Long(aniValue, "toLong", ":l", &value) == ANI_OK, "create long failed");
        valueObj = static_cast<int64_t>(value);
        return true;
    }
    env->FindClass("std.core.String", &optionClass);
    CHKCF(env->Object_InstanceOf(aniValue, optionClass, &res) == ANI_OK, "create str failed");
    if (res) {
        auto stringContent = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(aniValue));
        valueObj = stringContent;
        return true;
    }
    env->FindClass("escompat.Array", &optionClass);
    CHKCF(env->Object_InstanceOf(aniValue, optionClass, &res) == ANI_OK, "create Array failed");
    if (res) {
        valueObj = ANIUtils_ANIArrayToStdVector(env, static_cast<ani_array>(aniValue));
        return true;
    } else {
        valueObj = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(env, aniValue);
        return true;
    };
    return true;
}

onScreenCallbackTaihe::onScreenCallbackTaihe(
    std::shared_ptr<taihe::callback<void(OnscreenAwarenessInfo const &)>> callback): callback_(callback)
{
    FI_HILOGI("onScreenCallbackTaihe enter");
}

void onScreenCallbackTaihe::OnScreenAwareness(const OnScreen::OnscreenAwarenessInfo& info)
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<EntityInfo> taiheVector;
    for (const auto &entityInfo : info.entityInfo) {
        ::taihe::map<::taihe::string, uintptr_t> result(entityInfo.entityInfo.size());
        for (const auto &[key, value] : entityInfo.entityInfo) {
            ani_object aniValue;
            AniOnscreenEvent::ValueObjToAni(value, aniValue);
            result.emplace(key, reinterpret_cast<uintptr_t>(aniValue));
        }
        taiheVector.push_back(EntityInfo{ .entityName = entityInfo.entityName, .entityInfo = result, });
    };

    OnscreenAwarenessInfo cbInfo = {
        .resultCode = info.resultCode,
        .timestamp = info.timestamp,
        .bundleName = optional<string>(std::in_place_t {}, string(info.bundleName)),
        .appID = optional<string>(std::in_place_t {}, string(info.appID)),
        .appIndex = optional<int32_t>(std::in_place_t {}, info.appIndex),
        .pageId = optional<string>(std::in_place_t {}, string(info.pageId)),
        .sampleId = optional<string>(std::in_place_t {}, string(info.sampleId)),
        .collectStrategy = optional<int32_t>(std::in_place_t {}, info.collectStrategy),
        .displayId = optional<int64_t>(std::in_place_t{}, info.displayId),
        .windowId = optional<int32_t>(std::in_place_t {}, info.windowId),
        .entityInfo = optional<array<EntityInfo>>(std::in_place_t {},
            taihe::array<EntityInfo>(taihe::copy_data_t{}, taiheVector.data(), taiheVector.size())),
    };
    if (callback_ != nullptr) {
        (*callback_)(cbInfo);
    }
}
} // namespace ANI::MultimodalAwareness
