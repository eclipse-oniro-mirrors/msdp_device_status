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

#ifndef SEQUENCEABLE_TEST_H
#define SEQUENCEABLE_TEST_H

#include <gtest/gtest.h>

#include "sequenceable_cooperate_options.h"
#include "sequenceable_drag_data.h"
#include "sequenceable_drag_result.h"
#include "sequenceable_drag_visible.h"
#include "sequenceable_preview_animation.h"
#include "sequenceable_preview_style.h"
#include "sequenceable_rotate_window.h"


namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SequencableTest : public testing::Test {
public:
    static void SetUpTestCase();
    void SetUp();
    void TearDown();
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SEQUENCEABLE_TEST_H
