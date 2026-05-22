/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef USER_STATUS_NAPI_UTIL_H
#define USER_STATUS_NAPI_UTIL_H

#include <chrono>
#include <functional>
#include <string>


#include "ani.h"
#include "taihe/runtime.hpp"

#include "comfort_reminder_data.h"
#include "user_status_data.h"
#include "play_ability_status_data.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
constexpr uint32_t FEATURE_UNKNOWN = 0;
constexpr uint32_t FEATURE_USER_PLAY_ABILITY_FATIGUE = 5;
constexpr uint32_t FEATURE_ANTI_MISTOUCH = 6;
constexpr uint32_t FEATURE_USER_GESTURE = 7;
constexpr uint32_t FEATURE_USER_FACE = 8;
constexpr uint32_t FEATURE_USER_PLAYING = 9;
constexpr uint32_t FEATURE_USER_PREFERENCE_APP = 10;
constexpr uint32_t FEATURE_USER_FACE_ANGLE = 11;
constexpr uint32_t FEATURE_USER_BLOW = 12;
constexpr uint32_t FEATURE_USER_MOOD = 13;
constexpr uint32_t FEATURE_TIME_TUNNEL = 14;
constexpr uint32_t FEATURE_COMFORT_REMINDER = 15;
constexpr uint32_t FEATURE_UNDERAGE_MODEL = 16;
constexpr uint32_t FEATURE_ENV_SOUND = 17;
constexpr uint32_t FEATURE_RAPIDCAPTURE_ANTI_MISTOUCH = 18;
constexpr uint32_t FEATURE_LEM_EXT_SCREEN_ANTI_MISTOUCH = 19;
constexpr uint32_t FEATURE_UNSUPPORTED = 20;
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
#endif // USER_STATUS_NAPI_UTIL_H