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

import motion from '@ohos.multimodalAwareness.motion';
import { BusinessError, AsyncCallback} from '@ohos.base';

const Tag:String = "motion"

const ERR_INVALID_PARAM = 1;
const  OVERTIME_QUERY: long = 1000;
const  WAIT_OPER: long = 10000;
function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}

function test_motion() {
    let fun_name: string = 'test_motion';
    console.log(Tag, `into func on ${fun_name}`);
    let fnCallBack = (info: motion.OperatingHandStatus) => {
        console.log(Tag,  `motion ${fun_name} on success`);
        console.log(Tag,  `motion ${fun_name} on success ${JSON.stringify(info)}`);
    };
    try {
        motion.on('operatingHandChanged', fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `${fun_name} {on} check finished.`);
    wait(WAIT_OPER);
    try {
        let status : motion.OperatingHandStatus = motion.getRecentOperatingHandStatus();
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `${fun_name} {getRecentOperatingHandStatus} check finished.`);
    try {
        motion.off('operatingHandChanged', fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `${fun_name} {off} check finished.`);
    console.log(Tag, `end func on ${fun_name}`);
}

function main() {
    console.println(Tag + ` into main`);
    test_motion();
    console.println(Tag + ` out main`);
}