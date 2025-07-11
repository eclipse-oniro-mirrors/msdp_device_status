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

#ifndef I_ON_SCREEN_ALGORITHM_H
#define I_ON_SCREEN_ALGORITHM_H

#include "on_screen_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class IOnScreenAlgorithm {
public:
    IOnScreenAlgorithm() = default;
    virtual ~IOnScreenAlgorithm() = default;

    virtual int32_t GetPageContent(const OnScreenCallingContext &context, const ContentOption &option,
        PageContent &pageContent) = 0;
    virtual int32_t SendControlEvent(const OnScreenCallingContext &context, const ControlEvent &event) = 0;
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_ON_SCREEN_ALGORITHM_H