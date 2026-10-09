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

#ifndef OHOS_ANI_BEHAVIOR_AWARENESS_H
#define OHOS_ANI_BEHAVIOR_AWARENESS_H

#include "ohos.multimodalAwareness.behaviorAwareness.proj.hpp"
#include "ohos.multimodalAwareness.behaviorAwareness.impl.hpp"
#include "ani.h"
#include "fi_log.h"
#include <map>
#include <stdexcept>
#include "taihe/runtime.hpp"
#include "behavior_awareness_manager.h"
#include "behavior_awareness_callback_stub.h"

namespace ANI::MultimodalAwareness {

void OnPerception(ohos::multimodalAwareness::behaviorAwareness::SubscribeInfo info,
    taihe::callback_view<void(ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)> callback);
void OffPerception(
    taihe::optional_view<taihe::callback<void(
        ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)>> callback);
void SubmitFeedback(ohos::multimodalAwareness::behaviorAwareness::FeedbackData feedback);

} // namespace ANI::MultimodalAwareness
#endif // OHOS_ANI_BEHAVIOR_AWARENESS_H
